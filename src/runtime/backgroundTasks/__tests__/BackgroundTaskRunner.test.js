'use strict';

/**
 * BackgroundTaskRunner — Finding 3.6 remediation unit tests.
 *
 * taskRegistry is mocked so tests can exercise every criticality/retryPolicy
 * combination (including 'startup-critical', which no real production task
 * currently uses — see taskRegistry.js header) without touching the real
 * registry file.
 */

jest.mock('../taskRegistry', () => ({
  getTaskDefinition: jest.fn(),
}));

const { getTaskDefinition } = require('../taskRegistry');
const { runTask, UnregisteredTaskError } = require('../BackgroundTaskRunner');
const { currentTask } = require('../taskContext');

function def(overrides = {}) {
  return {
    subsystem:   'test-subsystem',
    owner:       'test-owner',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'test',
    ...overrides,
  };
}

function fakeMetrics() {
  return {
    backgroundTasksStartedTotal:   { inc: jest.fn() },
    backgroundTasksCompletedTotal: { inc: jest.fn() },
    backgroundTasksFailedTotal:    { inc: jest.fn() },
    backgroundTaskDurationSeconds: { observe: jest.fn() },
    backgroundTaskTimeoutsTotal:   { inc: jest.fn() },
    backgroundTaskRetriesTotal:    { inc: jest.fn() },
  };
}

function fakeEmit() {
  const events = [];
  const emit = (level, event, data) => events.push({ level, event, data });
  emit.events = events;
  return emit;
}

beforeEach(() => {
  getTaskDefinition.mockReset();
});

describe('BackgroundTaskRunner.runTask', () => {
  test('unregistered task name rejects with UnregisteredTaskError, does not throw synchronously', async () => {
    getTaskDefinition.mockReturnValue(null);
    await expect(runTask('nope', async () => {})).rejects.toThrow(UnregisteredTaskError);
  });

  test('successful sync task resolves { ok: true, result }', async () => {
    getTaskDefinition.mockReturnValue(def());
    const metrics = fakeMetrics();
    const r = await runTask('t', () => 42, { _metrics: metrics, _emit: () => {} });
    expect(r).toEqual({ ok: true, result: 42 });
    expect(metrics.backgroundTasksStartedTotal.inc).toHaveBeenCalledWith({ task: 't' });
    expect(metrics.backgroundTasksCompletedTotal.inc).toHaveBeenCalledWith({ task: 't' });
    expect(metrics.backgroundTaskDurationSeconds.observe).toHaveBeenCalledWith({ task: 't' }, expect.any(Number));
  });

  test('successful async task resolves { ok: true, result }', async () => {
    getTaskDefinition.mockReturnValue(def());
    const r = await runTask('t', async () => 'done', { _emit: () => {}, _metrics: fakeMetrics() });
    expect(r).toEqual({ ok: true, result: 'done' });
  });

  // ── Containment: sync throw ──────────────────────────────────────────────

  test('non-critical task: synchronous throw is contained, never rethrown', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'non-critical' }));
    const metrics = fakeMetrics();
    const r = await runTask('t', () => { throw new Error('sync-boom'); }, { _metrics: metrics, _emit: () => {} });
    expect(r.ok).toBe(false);
    expect(r.error.message).toBe('sync-boom');
    expect(metrics.backgroundTasksFailedTotal.inc).toHaveBeenCalledWith({ task: 't', reason: 'rejected' });
  });

  // ── Containment: rejected promise ────────────────────────────────────────

  test('non-critical task: rejected promise is contained, never rethrown', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'non-critical' }));
    const r = await runTask('t', async () => { throw new Error('async-boom'); }, { _emit: () => {}, _metrics: fakeMetrics() });
    expect(r.ok).toBe(false);
    expect(r.error.message).toBe('async-boom');
  });

  test('critical (non-startup) task: rejected promise is also contained, never rethrown', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'critical' }));
    const r = await runTask('t', async () => { throw new Error('boom'); }, { _emit: () => {}, _metrics: fakeMetrics() });
    expect(r.ok).toBe(false);
  });

  // ── startup-critical: fail-fast preserved ────────────────────────────────

  test('startup-critical task: rejection is rethrown (fail-fast preserved)', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'startup-critical' }));
    await expect(
      runTask('t', async () => { throw new Error('startup-boom'); }, { _emit: () => {}, _metrics: fakeMetrics() }),
    ).rejects.toThrow('startup-boom');
  });

  test('startup-critical task: successful run still resolves normally', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'startup-critical' }));
    const r = await runTask('t', async () => 'ok', { _emit: () => {}, _metrics: fakeMetrics() });
    expect(r).toEqual({ ok: true, result: 'ok' });
  });

  // ── Timeout ───────────────────────────────────────────────────────────────

  test('timeout: task exceeding timeoutMs is treated as a failure, not left hanging', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'non-critical', timeoutMs: 30 }));
    const metrics = fakeMetrics();
    // The task's own timer is uncancellable (Promise.race can't abort it) —
    // kept short and unref'd so it can't hold the test process open past
    // the timeout race resolving.
    const r = await runTask('t', () => new Promise(resolve => {
      const h = setTimeout(resolve, 200);
      if (h.unref) h.unref();
    }), { _metrics: metrics, _emit: () => {} });
    expect(r.ok).toBe(false);
    expect(r.error._isTimeout).toBe(true);
    expect(metrics.backgroundTaskTimeoutsTotal.inc).toHaveBeenCalledWith({ task: 't' });
    expect(metrics.backgroundTasksFailedTotal.inc).toHaveBeenCalledWith({ task: 't', reason: 'timeout' });
  });

  test('no timeout applied when timeoutMs is null', async () => {
    getTaskDefinition.mockReturnValue(def({ timeoutMs: null }));
    const r = await runTask('t', () => new Promise(resolve => setTimeout(() => resolve('slow-but-fine'), 20)), { _emit: () => {}, _metrics: fakeMetrics() });
    expect(r).toEqual({ ok: true, result: 'slow-but-fine' });
  });

  // ── Runner-level retry (retryPolicy: 'runner') ───────────────────────────

  test('retry success: fails once, succeeds on retry, returns ok:true', async () => {
    getTaskDefinition.mockReturnValue(def({ retryPolicy: 'runner' }));
    const metrics = fakeMetrics();
    let calls = 0;
    const r = await runTask('t', async () => {
      calls++;
      if (calls === 1) throw new Error('first-attempt-fails');
      return 'second-attempt-succeeds';
    }, { retries: 1, retryDelayMs: 1, _metrics: metrics, _emit: () => {} });

    expect(r).toEqual({ ok: true, result: 'second-attempt-succeeds' });
    expect(calls).toBe(2);
    expect(metrics.backgroundTaskRetriesTotal.inc).toHaveBeenCalledWith({ task: 't' });
  });

  test('retry exhaustion: fails every attempt, returns ok:false after retries+1 calls', async () => {
    getTaskDefinition.mockReturnValue(def({ retryPolicy: 'runner' }));
    let calls = 0;
    const r = await runTask('t', async () => { calls++; throw new Error('always-fails'); },
      { retries: 2, retryDelayMs: 1, _emit: () => {}, _metrics: fakeMetrics() });

    expect(r.ok).toBe(false);
    expect(r.error.message).toBe('always-fails');
    expect(calls).toBe(3); // initial attempt + 2 retries
  });

  test('retries option is ignored when retryPolicy is not "runner" (single attempt)', async () => {
    getTaskDefinition.mockReturnValue(def({ retryPolicy: 'internal' }));
    let calls = 0;
    const r = await runTask('t', async () => { calls++; throw new Error('fails'); },
      { retries: 5, retryDelayMs: 1, _emit: () => {}, _metrics: fakeMetrics() });

    expect(r.ok).toBe(false);
    expect(calls).toBe(1);
  });

  // ── Structured logging ───────────────────────────────────────────────────

  test('emits BACKGROUND_TASK_COMPLETED with expected fields on success', async () => {
    getTaskDefinition.mockReturnValue(def({ subsystem: 'sub', owner: 'own', criticality: 'critical' }));
    const emit = fakeEmit();
    await runTask('my-task', async () => 'x', { _emit: emit, _metrics: fakeMetrics() });

    const completed = emit.events.find(e => e.event === 'BACKGROUND_TASK_COMPLETED');
    expect(completed).toBeDefined();
    expect(completed.level).toBe('INFO');
    expect(completed.data).toMatchObject({
      task: 'my-task', subsystem: 'sub', owner: 'own', criticality: 'critical', attempt: 1,
    });
    expect(typeof completed.data.executionTimeMs).toBe('number');
  });

  test('emits BACKGROUND_TASK_FAILED with task/error/stack/reason on failure', async () => {
    getTaskDefinition.mockReturnValue(def({ subsystem: 'sub', owner: 'own' }));
    const emit = fakeEmit();
    await runTask('my-task', async () => { throw new Error('specific-failure'); }, { _emit: emit, _metrics: fakeMetrics() });

    const failed = emit.events.find(e => e.event === 'BACKGROUND_TASK_FAILED');
    expect(failed).toBeDefined();
    expect(failed.level).toBe('ERROR');
    expect(failed.data.task).toBe('my-task');
    expect(failed.data.error).toBe('specific-failure');
    expect(typeof failed.data.stack).toBe('string');
    expect(failed.data.reason).toBe('rejected');
    expect(failed.data.retryCount).toBe(0);
    expect(failed.data.willRetry).toBe(false);
  });

  test('emits FATAL level (not ERROR) for a failed startup-critical task', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'startup-critical' }));
    const emit = fakeEmit();
    await expect(runTask('t', async () => { throw new Error('x'); }, { _emit: emit, _metrics: fakeMetrics() })).rejects.toThrow();

    const failed = emit.events.find(e => e.event === 'BACKGROUND_TASK_FAILED');
    expect(failed.level).toBe('FATAL');
  });

  // ── Task context propagation ─────────────────────────────────────────────

  test('currentTask() is populated inside the task body and null outside', async () => {
    getTaskDefinition.mockReturnValue(def({ subsystem: 'sub', owner: 'own', criticality: 'critical' }));
    expect(currentTask()).toBeNull();

    let observed = null;
    await runTask('ctx-task', async () => {
      observed = currentTask();
    }, { _emit: () => {}, _metrics: fakeMetrics() });

    expect(observed).toMatchObject({ taskName: 'ctx-task', subsystem: 'sub', owner: 'own', criticality: 'critical' });
    expect(currentTask()).toBeNull();
  });

  // ── Concurrency ───────────────────────────────────────────────────────────

  test('concurrent independent task failures do not interfere with each other', async () => {
    getTaskDefinition.mockImplementation((name) => def({ criticality: 'non-critical' }));
    const metrics = fakeMetrics();

    const results = await Promise.all([
      runTask('task-a', async () => { throw new Error('fail-a'); }, { _emit: () => {}, _metrics: metrics }),
      runTask('task-b', async () => 'ok-b', { _emit: () => {}, _metrics: metrics }),
      runTask('task-c', async () => { throw new Error('fail-c'); }, { _emit: () => {}, _metrics: metrics }),
      runTask('task-d', async () => 'ok-d', { _emit: () => {}, _metrics: metrics }),
    ]);

    expect(results[0]).toMatchObject({ ok: false, error: expect.objectContaining({ message: 'fail-a' }) });
    expect(results[1]).toEqual({ ok: true, result: 'ok-b' });
    expect(results[2]).toMatchObject({ ok: false, error: expect.objectContaining({ message: 'fail-c' }) });
    expect(results[3]).toEqual({ ok: true, result: 'ok-d' });
  });

  test('a failing task never crashes the process (no unhandled rejection observable)', async () => {
    getTaskDefinition.mockReturnValue(def({ criticality: 'non-critical' }));
    // If runTask() ever let this escape, Node would emit a real
    // 'unhandledRejection' process event; awaiting it directly here proves
    // the returned promise always resolves (never rejects) for this criticality.
    await expect(
      runTask('t', async () => { throw new Error('should stay contained'); }, { _emit: () => {}, _metrics: fakeMetrics() }),
    ).resolves.toMatchObject({ ok: false });
  });
});
