'use strict';

/**
 * Persistence Recovery Journal Worker — FAILOVER-1 remediation
 *
 * journalWorker.js replays entries from the filesystem journal (journal.js)
 * back into the PostgreSQL-backed recovery queue (queue.js) once PostgreSQL
 * is reachable again. All dependencies are mocked here — durability of the
 * journal itself is covered by journal.test.js; this file proves the
 * worker's replay/skip/ordering/idempotency logic.
 *
 * JW-01  _replayOne: success → queue.enqueue called, then journal.removeEntry called
 * JW-02  _replayOne: queue.enqueue rejects → entry NOT removed, returns false
 * JW-03  _replayOne: removeEntry rejecting still resolves the call (never throws upward)
 * JW-04  _poll: skips entirely when PostgreSQL is not enabled (no replay attempted)
 * JW-05  _poll: skips entirely when queue is not ready
 * JW-06  _poll: replays every entry in order when PostgreSQL is ready
 * JW-07  _poll: stops at the first failure in a batch (doesn't burn through the rest)
 * JW-08  _poll: always refreshes journal depth/age/bytes gauges, even when PG not ready
 * JW-09  start()/stop()/isRunning() lifecycle
 */

// Explicit factories (not bare automocks) — an automock still has to
// `require()` the real module once to introspect its shape, which would
// execute pool.js's real top-level side effects (it schedules its own
// 'postgres-readiness-monitor' setInterval at require time). Explicit
// factories never touch the real modules at all.
jest.mock('../journal', () => ({
  appendEntry:  jest.fn(),
  listEntries:  jest.fn(),
  removeEntry:  jest.fn(),
  getStats:     jest.fn(),
}));
jest.mock('../queue', () => ({
  enqueue:   jest.fn(),
  _isReady:  jest.fn(),
}));
jest.mock('../../../infra/postgres/pool', () => ({
  isEnabled: jest.fn(),
}));
jest.mock('../../../observability/metrics', () => ({
  prqJournalDepth:                 { set: jest.fn() },
  prqJournalOldestEntryAgeSeconds: { set: jest.fn() },
  prqJournalBytes:                 { set: jest.fn() },
  prqJournalReplayedTotal:         { inc: jest.fn() },
  prqJournalReplayFailedTotal:     { inc: jest.fn() },
  prqJournalReplayDurationMs:      { observe: jest.fn() },
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const journal    = require('../journal');
const queue      = require('../queue');
const pgPool     = require('../../../infra/postgres/pool');
const obsMetrics = require('../../../observability/metrics');
const journalWorker = require('../journalWorker');

function makeEntry(overrides = {}) {
  return {
    journalId: 'a'.repeat(64),
    operation: {
      operationId:   'att:1',
      operationType: 'ATTESTATION_SAVE',
      service:       'attestation',
      payload:       { attestationId: '1' },
    },
    journaledAt: new Date().toISOString(),
    ...overrides,
  };
}

// A fake, immediately-settling task runner mirroring BackgroundTaskRunner's
// { ok, error } contract, so _poll tests don't depend on the real
// taskRegistry/metrics wiring.
async function fakeTaskRunner(_name, fn) {
  try {
    const result = await fn();
    return { ok: true, result };
  } catch (error) {
    return { ok: false, error };
  }
}

beforeEach(() => {
  jest.clearAllMocks();
  journalWorker.stop();
});

describe('_replayOne', () => {
  test('JW-01: success calls queue.enqueue then journal.removeEntry, returns true', async () => {
    queue.enqueue.mockResolvedValueOnce(undefined);
    journal.removeEntry.mockResolvedValueOnce(undefined);

    const entry = makeEntry();
    const ok = await journalWorker._replayOne(entry);

    expect(ok).toBe(true);
    expect(queue.enqueue).toHaveBeenCalledWith(entry.operation);
    expect(journal.removeEntry).toHaveBeenCalledWith(entry.journalId);
    expect(obsMetrics.prqJournalReplayedTotal.inc).toHaveBeenCalled();
  });

  test('JW-02: queue.enqueue rejecting leaves the entry in place, returns false', async () => {
    queue.enqueue.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const entry = makeEntry();
    const ok = await journalWorker._replayOne(entry);

    expect(ok).toBe(false);
    expect(journal.removeEntry).not.toHaveBeenCalled();
    expect(obsMetrics.prqJournalReplayFailedTotal.inc).toHaveBeenCalledWith({ operationType: 'ATTESTATION_SAVE' });
  });

  test('JW-03: removeEntry rejecting is treated as replay failure, not an unhandled rejection', async () => {
    queue.enqueue.mockResolvedValueOnce(undefined);
    journal.removeEntry.mockRejectedValueOnce(new Error('EACCES'));

    const entry = makeEntry();
    await expect(journalWorker._replayOne(entry)).resolves.toBe(false);
  });
});

describe('_poll', () => {
  // _poll() no-ops entirely while _running is false (the module's own
  // start/stop guard) — start() is required so directly-invoked _poll() calls
  // actually execute their body. start()/_poll() both self-reschedule via a
  // real setTimeout though, so fake timers keep that from ever registering a
  // real OS-level timer (which would otherwise report as a Jest open handle
  // even after stop()'s clearTimeout, since the reschedule happens inside
  // the same _poll() call this test already awaited).
  beforeEach(() => {
    jest.useFakeTimers();
    journalWorker.start();
  });
  afterEach(() => {
    journalWorker.stop();
    jest.useRealTimers();
  });

  test('JW-04: skips replay entirely when PostgreSQL is not enabled', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    queue._isReady.mockReturnValue(false);
    journal.getStats.mockResolvedValue({ depth: 0, oldestEntryAgeMs: 0, totalBytes: 0 });

    await journalWorker._poll({ _taskRunner: { runTask: fakeTaskRunner } });

    expect(journal.listEntries).not.toHaveBeenCalled();
  });

  test('JW-05: skips replay entirely when queue is not ready', async () => {
    pgPool.isEnabled.mockReturnValue(true);
    queue._isReady.mockReturnValue(false);
    journal.getStats.mockResolvedValue({ depth: 0, oldestEntryAgeMs: 0, totalBytes: 0 });

    await journalWorker._poll({ _taskRunner: { runTask: fakeTaskRunner } });

    expect(journal.listEntries).not.toHaveBeenCalled();
  });

  test('JW-06: replays every entry in order when PostgreSQL is ready', async () => {
    pgPool.isEnabled.mockReturnValue(true);
    queue._isReady.mockReturnValue(true);
    journal.getStats.mockResolvedValue({ depth: 2, oldestEntryAgeMs: 1000, totalBytes: 200 });

    const e1 = makeEntry({ journalId: 'a'.repeat(64), operation: { operationId: 'att:1', operationType: 'ATTESTATION_SAVE' } });
    const e2 = makeEntry({ journalId: 'b'.repeat(64), operation: { operationId: 'att:2', operationType: 'ATTESTATION_SAVE' } });
    journal.listEntries.mockResolvedValue([e1, e2]);
    queue.enqueue.mockResolvedValue(undefined);
    journal.removeEntry.mockResolvedValue(undefined);

    await journalWorker._poll({ _taskRunner: { runTask: fakeTaskRunner } });

    expect(queue.enqueue).toHaveBeenCalledTimes(2);
    expect(queue.enqueue).toHaveBeenNthCalledWith(1, e1.operation);
    expect(queue.enqueue).toHaveBeenNthCalledWith(2, e2.operation);
    expect(journal.removeEntry).toHaveBeenCalledTimes(2);
  });

  test('JW-07: stops at the first failure in a batch', async () => {
    pgPool.isEnabled.mockReturnValue(true);
    queue._isReady.mockReturnValue(true);
    journal.getStats.mockResolvedValue({ depth: 2, oldestEntryAgeMs: 1000, totalBytes: 200 });

    const e1 = makeEntry({ journalId: 'a'.repeat(64), operation: { operationId: 'att:1', operationType: 'ATTESTATION_SAVE' } });
    const e2 = makeEntry({ journalId: 'b'.repeat(64), operation: { operationId: 'att:2', operationType: 'ATTESTATION_SAVE' } });
    journal.listEntries.mockResolvedValue([e1, e2]);
    queue.enqueue.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    await journalWorker._poll({ _taskRunner: { runTask: fakeTaskRunner } });

    expect(queue.enqueue).toHaveBeenCalledTimes(1);
    expect(journal.removeEntry).not.toHaveBeenCalled();
  });

  test('JW-08: refreshes journal depth/age/bytes gauges even when PostgreSQL is not ready', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    queue._isReady.mockReturnValue(false);
    journal.getStats.mockResolvedValue({ depth: 5, oldestEntryAgeMs: 42_000, totalBytes: 9001 });

    await journalWorker._poll({ _taskRunner: { runTask: fakeTaskRunner } });

    expect(obsMetrics.prqJournalDepth.set).toHaveBeenCalledWith({}, 5);
    expect(obsMetrics.prqJournalOldestEntryAgeSeconds.set).toHaveBeenCalledWith({}, 42);
    expect(obsMetrics.prqJournalBytes.set).toHaveBeenCalledWith({}, 9001);
  });
});

describe('lifecycle', () => {
  test('JW-09: start()/stop()/isRunning() lifecycle', () => {
    jest.useFakeTimers();
    try {
      expect(journalWorker.isRunning()).toBe(false);
      journalWorker.start();
      expect(journalWorker.isRunning()).toBe(true);
      journalWorker.start(); // idempotent
      expect(journalWorker.isRunning()).toBe(true);
      journalWorker.stop();
      expect(journalWorker.isRunning()).toBe(false);
      journalWorker.stop(); // idempotent
      expect(journalWorker.isRunning()).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });
});
