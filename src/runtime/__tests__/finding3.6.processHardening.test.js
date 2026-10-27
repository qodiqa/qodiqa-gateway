'use strict';

/**
 * Finding 3.6 — criticality-aware global unhandledRejection/uncaughtException
 * handler tests.
 *
 * These directly exercise the real process-level listeners registered by
 * applyProcessHardening() via process.emit(...), the standard technique for
 * testing Node global error handlers without actually crashing the test
 * process. Listeners are removed before/after every test so this file
 * neither depends on nor leaks state to any other test file sharing the
 * same Jest worker process.
 */

const { applyProcessHardening } = require('../processHardening');
const { runWithTask } = require('../backgroundTasks/taskContext');

function install({ emit, metrics, exit } = {}) {
  applyProcessHardening(emit || (() => {}), {
    _metrics: metrics || { backgroundTasksFailedTotal: { inc: jest.fn() } },
    _exit:    exit || jest.fn(),
  });
}

function fakeEmit() {
  const events = [];
  const emit = (level, event, data) => events.push({ level, event, data });
  emit.events = events;
  return emit;
}

beforeEach(() => {
  process.removeAllListeners('unhandledRejection');
  process.removeAllListeners('uncaughtException');
});

afterEach(() => {
  process.removeAllListeners('unhandledRejection');
  process.removeAllListeners('uncaughtException');
});

describe('unhandledRejection', () => {
  test('with no active BackgroundTaskRunner task context: exits (fail-fast preserved — primary request path)', () => {
    const exit = jest.fn();
    const emit = fakeEmit();
    install({ emit, exit });

    process.emit('unhandledRejection', new Error('primary-path-bug'), Promise.resolve());

    expect(exit).toHaveBeenCalledWith(1);
    const fatal = emit.events.find(e => e.event === 'UNHANDLED_REJECTION');
    expect(fatal).toBeDefined();
    expect(fatal.level).toBe('FATAL');
    expect(fatal.data.task).toBeNull();
  });

  test('inside a non-critical task context: does NOT exit, logs BACKGROUND_TASK_UNHANDLED_ESCAPE, increments metric', async () => {
    const exit = jest.fn();
    const emit = fakeEmit();
    const metrics = { backgroundTasksFailedTotal: { inc: jest.fn() } };
    install({ emit, metrics, exit });

    const ctx = { taskName: 'transparency-gap-scan', subsystem: 'transparency-log', owner: 'platform-security', criticality: 'non-critical' };
    await runWithTask(ctx, async () => {
      process.emit('unhandledRejection', new Error('escaped-bug'), Promise.resolve());
    });

    expect(exit).not.toHaveBeenCalled();
    const escape = emit.events.find(e => e.event === 'BACKGROUND_TASK_UNHANDLED_ESCAPE');
    expect(escape).toBeDefined();
    expect(escape.level).toBe('ERROR');
    expect(escape.data).toMatchObject({ task: 'transparency-gap-scan', subsystem: 'transparency-log', criticality: 'non-critical' });
    expect(metrics.backgroundTasksFailedTotal.inc).toHaveBeenCalledWith({ task: 'transparency-gap-scan', reason: 'escaped_isolation' });
  });

  test('inside a critical (non-startup) task context: does NOT exit', async () => {
    const exit = jest.fn();
    const emit = fakeEmit();
    install({ emit, exit });

    const ctx = { taskName: 'key-rotation-tick', subsystem: 'crypto-key-management', owner: 'platform-security', criticality: 'critical' };
    await runWithTask(ctx, async () => {
      process.emit('unhandledRejection', new Error('escaped-bug'), Promise.resolve());
    });

    expect(exit).not.toHaveBeenCalled();
    expect(emit.events.find(e => e.event === 'BACKGROUND_TASK_UNHANDLED_ESCAPE')).toBeDefined();
  });

  test('inside a startup-critical task context: still exits (fail-fast preserved)', async () => {
    const exit = jest.fn();
    const emit = fakeEmit();
    install({ emit, exit });

    const ctx = { taskName: 'consent-subscriber-start', subsystem: 'consent', owner: 'platform-security', criticality: 'startup-critical' };
    await runWithTask(ctx, async () => {
      process.emit('unhandledRejection', new Error('startup-bug'), Promise.resolve());
    });

    expect(exit).toHaveBeenCalledWith(1);
    const fatal = emit.events.find(e => e.event === 'UNHANDLED_REJECTION');
    expect(fatal).toBeDefined();
    expect(fatal.data.task).toBe('consent-subscriber-start');
  });
});

describe('uncaughtException', () => {
  test('with no active BackgroundTaskRunner task context: exits (fail-fast preserved)', () => {
    const exit = jest.fn();
    const emit = fakeEmit();
    install({ emit, exit });

    process.emit('uncaughtException', new Error('primary-path-bug'));

    expect(exit).toHaveBeenCalledWith(1);
    const fatal = emit.events.find(e => e.event === 'UNCAUGHT_EXCEPTION');
    expect(fatal).toBeDefined();
    expect(fatal.level).toBe('FATAL');
  });

  test('inside a non-critical task context: does NOT exit, logs BACKGROUND_TASK_UNHANDLED_ESCAPE', async () => {
    const exit = jest.fn();
    const emit = fakeEmit();
    const metrics = { backgroundTasksFailedTotal: { inc: jest.fn() } };
    install({ emit, metrics, exit });

    const ctx = { taskName: 'dashboard-sse-snapshot', subsystem: 'dashboard', owner: 'platform-ops', criticality: 'non-critical' };
    await runWithTask(ctx, async () => {
      process.emit('uncaughtException', new Error('escaped-sync-bug'));
    });

    expect(exit).not.toHaveBeenCalled();
    const escape = emit.events.find(e => e.event === 'BACKGROUND_TASK_UNHANDLED_ESCAPE');
    expect(escape).toBeDefined();
    expect(metrics.backgroundTasksFailedTotal.inc).toHaveBeenCalledWith({ task: 'dashboard-sse-snapshot', reason: 'escaped_isolation' });
  });

  test('inside a startup-critical task context: still exits', async () => {
    const exit = jest.fn();
    const emit = fakeEmit();
    install({ emit, exit });

    const ctx = { taskName: 'crypto-init', subsystem: 'crypto', owner: 'platform-security', criticality: 'startup-critical' };
    await runWithTask(ctx, async () => {
      process.emit('uncaughtException', new Error('startup-bug'));
    });

    expect(exit).toHaveBeenCalledWith(1);
  });
});

describe('registration is idempotent / does not double-fire', () => {
  test('calling applyProcessHardening twice does not register duplicate listeners', () => {
    const exit = jest.fn();
    install({ exit });
    install({ exit }); // second call — should be a no-op per listenerCount guard

    process.emit('unhandledRejection', new Error('x'), Promise.resolve());

    expect(exit).toHaveBeenCalledTimes(1);
  });
});
