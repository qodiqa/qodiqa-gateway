'use strict';

/**
 * guard: every background task name passed to BackgroundTaskRunner.runTask('<name>') in product code must be
 * registered in taskRegistry.js. An unregistered name throws BACKGROUND_TASK_UNCLASSIFIED at its FIRST run — for the
 * audit-checkpoint scheduler that was 60 s after boot, as an unhandled rejection that ended the server process, and no
 * unit or component test kept a real server alive that long.
 *
 *   TR-01  every literal runTask('<name>') in src/, services/, middleware/, server.js and scripts/ (tests excluded) is in
 *          the registry
 *   TR-02  the checkpoint scheduler never lets a failed tick become an unhandled rejection
 */

const fs = require('fs');
const path = require('path');
const { REGISTRY } = require('../taskRegistry');

const ROOT = path.join(__dirname, '..', '..', '..', '..');

function jsFiles(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!['node_modules', '__tests__', '.stryker-tmp'].includes(e.name)) jsFiles(p, out); }
    else if (e.name.endsWith('.js') && !e.name.endsWith('.test.js')) out.push(p);
  }
  return out;
}

describe('background task registry coverage', () => {
  test('TR-01 every runTask name used by product code is registered', () => {
    const files = [...['src', 'services', 'middleware', 'scripts'].flatMap((d) => jsFiles(path.join(ROOT, d))), path.join(ROOT, 'server.js')];
    const used = new Map();
    for (const f of files) {
      const src = fs.readFileSync(f, 'utf8');
      for (const m of src.matchAll(/runTask\(\s*'([a-z0-9-]+)'/g)) used.set(m[1], path.relative(ROOT, f));
    }
    expect(used.has('audit-checkpoint')).toBe(true);
    const missing = [...used].filter(([name]) => !REGISTRY[name]).map(([name, f]) => `${name} (${f})`);
    expect(missing).toEqual([]);
  });

  test('TR-02 a failing checkpoint tick is reported, never an unhandled rejection', async () => {
    jest.useFakeTimers();
    const emitted = [];
    const unhandled = [];
    const onUnhandled = (e) => unhandled.push(e);
    process.on('unhandledRejection', onUnhandled);
    try {
      const { startCheckpointScheduler } = require('../../../core/audit/checkpoint/checkpointWriter');
      const stop = startCheckpointScheduler({
        tickMs: 1000,
        taskRunner: { runTask: () => Promise.reject(new Error('BACKGROUND_TASK_UNCLASSIFIED: simulated')) },
        emit: (level, event, extra) => emitted.push({ level, event, extra }),
        // GA-CKPT-RATE: the task runner now runs only when a checkpoint is due — 5 uncovered entries, no checkpoint yet.
        auditLog: { memorySnapshot: () => ({ modernCount: 5 }), LOG_PATH: 'unused' },
        pgPool: { isEnabled: () => false }, backend: {}, registrar: null, logStore: null, keyStore: {}, logPath: 'unused',
      });
      jest.advanceTimersByTime(1000);
      jest.useRealTimers();
      for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
      stop();
      expect(emitted).toEqual([expect.objectContaining({ level: 'ERROR', event: 'AUDIT_CHECKPOINT_TICK_FAILED' })]);
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
      jest.useRealTimers();
    }
  });
});
