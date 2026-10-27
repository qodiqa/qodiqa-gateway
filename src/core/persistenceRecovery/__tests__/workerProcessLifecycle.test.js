'use strict';

/**
 * ER — the persistence-recovery worker and journal worker must never be what keeps a process alive.
 * Their poll timers were the only ref'd background timers in the codebase; a worker started by an embedder and never
 * stopped (the in-process route-parity suites, under the CI coverage job's `jest --runInBand` with PostgreSQL enabled)
 * kept the process alive for hours. Proven in a real child process: start both workers, never stop them, and the child
 * must still exit on its own. A negative control (an ordinary ref'd timer) shows the harness detects a pinned process.
 */

const path = require('path');
const { spawn } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..', '..');
jest.setTimeout(30_000);

function runChild(code, waitMs) {
  return new Promise((resolve) => {
    const env = { ...process.env }; delete env.QODIQA_PG_ENABLED; delete env.PRQ_ENABLED;
    const child = spawn(process.execPath, ['-e', code], { cwd: REPO, env, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = ''; child.stderr.on('data', (d) => { stderr += d; });
    const started = Date.now();
    const timer = setTimeout(() => { child.kill(); resolve({ exited: false, stderr }); }, waitMs);
    child.on('exit', (code2) => { clearTimeout(timer); resolve({ exited: true, code: code2, ms: Date.now() - started, stderr }); });
  });
}

describe('persistence-recovery workers do not pin the process (ER)', () => {
  test('WPL-01 started and never stopped, the worker and journal worker still let the process exit', async () => {
    const r = await runChild(`
      const worker = require('./src/core/persistenceRecovery/worker');
      const journalWorker = require('./src/core/persistenceRecovery/journalWorker');
      worker.start(); journalWorker.start();
      if (!worker.isRunning()) { console.error('worker did not start'); process.exitCode = 3; }`, 10_000);
    expect(r.stderr).not.toMatch(/did not start/);
    expect(r.exited).toBe(true);
    expect(r.code).toBe(0);
  });

  test('WPL-02 negative control: an ordinary ref\'d timer does pin the child (the harness detects a hang)', async () => {
    const r = await runChild('setTimeout(() => {}, 60_000);', 3_000);
    expect(r.exited).toBe(false);
  });
});
