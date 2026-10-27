'use strict';

/**
 * FAILOVER-1 — Durable filesystem journal closes the CHAIN-3 residual gap
 *
 * CHAIN-3 (see docs/protocol/AUDIT-SCHEMA-V8.md) made the
 * PostgreSQL-backed persistence_recovery_queue the recovery queue's sole
 * durable store, correctly removing Redis as a single point of failure. It
 * left one disclosed residual risk: since the queue's own INSERT goes
 * against PostgreSQL — the same system whose failures it exists to recover
 * from — a sustained PostgreSQL outage occurring at the exact moment a write
 * AND its recovery-enqueue both fail meant the operation was lost with no
 * third, independent durable store to fall back to. For ATTESTATION_SAVE,
 * CERTIFICATION_SAVE, and PORTAL_VERIFICATION_SAVE specifically — unlike
 * AUDIT_CHAIN_PG_SAVE/EVIDENCE_CHAIN_SAVE, which are backstopped by the
 * always-active file-based audit-log.js chain — there was no fallback of any
 * kind.
 *
 * These tests exercise the real recoveryManager.enqueue()/
 * enqueueWebhookDelivery() and the real journalWorker against a REAL
 * temporary directory on disk (only the PostgreSQL-backed `queue` module and
 * `pgPool` are mocked, so "PostgreSQL is down" can be simulated by making
 * queue.enqueue() reject) — proving the operation survives a simulated
 * PostgreSQL+recovery-queue simultaneous failure end-to-end, and is
 * correctly replayed once PostgreSQL "recovers".
 *
 * FO1-01  ATTESTATION_SAVE survives PG+recovery-queue failure via the journal
 * FO1-02  CERTIFICATION_SAVE and PORTAL_VERIFICATION_SAVE survive identically
 * FO1-03  enqueueWebhookDelivery falls back to the journal identically
 * FO1-04  journalWorker replays a journaled entry back into the PG-backed
 *         queue once PostgreSQL recovers, and removes it from the journal
 * FO1-05  Replaying the same journal entry twice (simulated crash between a
 *         successful re-enqueue and journal cleanup) is idempotent — no
 *         duplicate loss, no duplicate journal entry
 * FO1-06  The one remaining unrecoverable case (PG AND local disk both down
 *         at once) is loudly surfaced via JOURNAL_WRITE_FAILED, never
 *         silently swallowed
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

jest.mock('../src/infra/postgres/pool', () => ({
  isEnabled: jest.fn(() => true),
}));
jest.mock('../src/core/persistenceRecovery/queue', () => ({
  enqueue:  jest.fn(),
  _isReady: jest.fn(() => true),
}));
jest.mock('../services/logger', () => ({ emit: jest.fn() }));

let TEST_DIR;

beforeEach(() => {
  TEST_DIR = path.join(os.tmpdir(), `qodiqa-failover1-test-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  process.env.QODIQA_PRQ_JOURNAL_DIR = TEST_DIR;
});

afterEach(() => {
  delete process.env.QODIQA_PRQ_JOURNAL_DIR;
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch { /* best-effort */ }
});

// journal.js (and everything requiring it) reads QODIQA_PRQ_JOURNAL_DIR at
// require time, so every test gets a fully fresh module registry — this
// also freshly re-requires the mocked queue/pool/logger modules each time
// (jest.mock's factory is re-invoked after resetModules()), so callers must
// always use the references THIS function returns, never a stale top-level
// binding captured before a reset.
function freshModules() {
  jest.resetModules();

  const pgPool = require('../src/infra/postgres/pool');
  const queue  = require('../src/core/persistenceRecovery/queue');
  const logger = require('../services/logger');
  pgPool.isEnabled.mockReturnValue(true);
  queue._isReady.mockReturnValue(true);

  return {
    pgPool,
    queue,
    logger,
    recoveryManager: require('../src/core/persistenceRecovery/recoveryManager'),
    journal:         require('../src/core/persistenceRecovery/journal'),
    journalWorker:   require('../src/core/persistenceRecovery/journalWorker'),
    OPERATION_TYPES: require('../src/core/persistenceRecovery/persistenceOperation').OPERATION_TYPES,
  };
}

async function fakeTaskRunner(_name, fn) {
  try { return { ok: true, result: await fn() }; }
  catch (error) { return { ok: false, error }; }
}

describe('FO1-01/02: enqueue() falls back to the journal when PG+recovery-queue both fail', () => {
  test('FO1-01: ATTESTATION_SAVE is durably journaled, not lost', async () => {
    const { recoveryManager, journal, queue, OPERATION_TYPES } = freshModules();

    const pgOutageErr = Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' });
    queue.enqueue.mockRejectedValueOnce(new Error('ECONNREFUSED')); // recovery-queue INSERT also fails

    const payload = { attestationId: 'a1111111-1111-1111-1111-111111111111', attestationDecision: 'ATTESTED' };
    await recoveryManager.enqueue(OPERATION_TYPES.ATTESTATION_SAVE, payload, pgOutageErr);

    const entries = await journal.listEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].operation.operationType).toBe(OPERATION_TYPES.ATTESTATION_SAVE);
    expect(entries[0].operation.payload).toEqual(payload);
  });

  test('FO1-02: CERTIFICATION_SAVE and PORTAL_VERIFICATION_SAVE survive identically', async () => {
    const { recoveryManager, journal, queue, OPERATION_TYPES } = freshModules();

    queue.enqueue.mockRejectedValue(new Error('ECONNREFUSED'));

    const certPayload   = { certificationId: 'c1', certificationLevel: 'GOLD', certificationDecision: 'CERTIFIED', score: 95 };
    const portalPayload = { verificationId: 'v1', artifactFingerprint: 'f'.repeat(64), overallResult: 'VERIFIED' };

    await recoveryManager.enqueue(OPERATION_TYPES.CERTIFICATION_SAVE, certPayload, new Error('down'));
    await recoveryManager.enqueue(OPERATION_TYPES.PORTAL_VERIFICATION_SAVE, portalPayload, new Error('down'));

    const entries = await journal.listEntries();
    expect(entries).toHaveLength(2);
    const types = entries.map(e => e.operation.operationType).sort();
    expect(types).toEqual([OPERATION_TYPES.CERTIFICATION_SAVE, OPERATION_TYPES.PORTAL_VERIFICATION_SAVE].sort());
  });
});

describe('FO1-03: enqueueWebhookDelivery falls back to the journal identically', () => {
  test('webhook delivery operation is durably journaled when the recovery queue is down', async () => {
    const { recoveryManager, journal, queue } = freshModules();

    queue.enqueue.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    await recoveryManager.enqueueWebhookDelivery({
      operationId: 'whd:endpoint-1:event-1',
      payload:     { endpointId: 'endpoint-1', eventId: 'event-1', eventType: 'artifact.verified', eventPayload: {} },
    });

    const entries = await journal.listEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].operation.operationId).toBe('whd:endpoint-1:event-1');
  });
});

describe('FO1-04/05: journalWorker replays journaled entries once PostgreSQL recovers', () => {
  test('FO1-04: a journaled entry is replayed into the PG-backed queue and removed from the journal', async () => {
    const { recoveryManager, journal, journalWorker, queue, OPERATION_TYPES } = freshModules();

    // Simulate the outage: enqueue fails, operation falls back to the journal.
    queue.enqueue.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const payload = { attestationId: 'a2222222-2222-2222-2222-222222222222', attestationDecision: 'ATTESTED' };
    await recoveryManager.enqueue(OPERATION_TYPES.ATTESTATION_SAVE, payload, new Error('down'));
    expect(await journal.listEntries()).toHaveLength(1);

    // Simulate recovery: queue.enqueue (i.e. PostgreSQL) now succeeds.
    queue.enqueue.mockResolvedValue(undefined);
    queue.enqueue.mockClear(); // isolate the replay-phase call count from the outage-phase call above

    // _poll() no-ops entirely while the worker isn't start()ed; fake timers
    // keep its self-rescheduling setTimeout from registering a real OS timer.
    jest.useFakeTimers();
    try {
      journalWorker.start();
      await journalWorker._poll({ _taskRunner: { runTask: fakeTaskRunner } });
    } finally {
      journalWorker.stop();
      jest.useRealTimers();
    }

    expect(queue.enqueue).toHaveBeenCalledWith(expect.objectContaining({
      operationType: OPERATION_TYPES.ATTESTATION_SAVE,
      payload,
    }));
    expect(await journal.listEntries()).toHaveLength(0);
  });

  test('FO1-05: replaying an entry twice (crash between re-enqueue and cleanup) is idempotent, no duplicate loss', async () => {
    const { recoveryManager, journal, journalWorker, queue, OPERATION_TYPES } = freshModules();

    queue.enqueue.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const payload = { attestationId: 'a3333333-3333-3333-3333-333333333333', attestationDecision: 'ATTESTED' };
    await recoveryManager.enqueue(OPERATION_TYPES.ATTESTATION_SAVE, payload, new Error('down'));

    const [entry] = await journal.listEntries();

    // First replay attempt succeeds. Clear the call count first so it
    // reflects only the two replay attempts below, not the initial
    // (rejected) outage-phase enqueue from recoveryManager.enqueue() above.
    queue.enqueue.mockResolvedValue(undefined);
    queue.enqueue.mockClear();
    const ok1 = await journalWorker._replayOne(entry);
    expect(ok1).toBe(true);

    // The real journal.removeEntry already ran as part of _replayOne, so to
    // faithfully simulate "crash before cleanup happened", re-append the
    // identical operation (same operationId) as if the file had never been
    // deleted, then replay it again — this proves a second replay of the
    // same logical operation is harmless (queue.enqueue's ON CONFLICT DO
    // UPDATE makes the PG side idempotent; here we assert the client-facing
    // contract: calling it twice with the same operation never throws and
    // always converges to a clean journal).
    await journal.appendEntry(entry.operation);
    const [reAppended] = await journal.listEntries();
    const ok2 = await journalWorker._replayOne(reAppended);
    expect(ok2).toBe(true);

    expect(queue.enqueue).toHaveBeenCalledTimes(2);
    expect(queue.enqueue).toHaveBeenNthCalledWith(1, expect.objectContaining({ operationId: entry.operation.operationId }));
    expect(queue.enqueue).toHaveBeenNthCalledWith(2, expect.objectContaining({ operationId: entry.operation.operationId }));
    expect(await journal.listEntries()).toHaveLength(0);
  });
});

describe('FO1-06: the one remaining unrecoverable case is loudly surfaced, never silent', () => {
  test('PG down AND local disk unwritable → JOURNAL_WRITE_FAILED is logged, no silent success', async () => {
    // Point QODIQA_PRQ_JOURNAL_DIR at a path that collides with an existing
    // FILE (not a directory), so fs.mkdir(..., { recursive: true }) fails
    // deterministically cross-platform — simulating an unwritable volume.
    const blockingFile = path.join(os.tmpdir(), `qodiqa-blocking-file-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.tmp`);
    fs.writeFileSync(blockingFile, 'not a directory', 'utf8');
    process.env.QODIQA_PRQ_JOURNAL_DIR = path.join(blockingFile, 'journal');

    try {
      const { recoveryManager, queue, logger, OPERATION_TYPES } = freshModules();
      queue.enqueue.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      await recoveryManager.enqueue(
        OPERATION_TYPES.ATTESTATION_SAVE,
        { attestationId: 'a4444444-4444-4444-4444-444444444444', attestationDecision: 'ATTESTED' },
        new Error('down'),
      );

      const journalWriteFailedCalls = logger.emit.mock.calls.filter(([, eventType]) => eventType === 'JOURNAL_WRITE_FAILED');
      expect(journalWriteFailedCalls.length).toBeGreaterThan(0);
    } finally {
      fs.unlinkSync(blockingFile);
    }
  });
});
