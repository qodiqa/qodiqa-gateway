'use strict';

/**
 * ER — regression for the CI coverage-gate hang. `npm run test:coverage` (runInBand, PostgreSQL enabled)
 * finished every test in ~15 min and then never exited: the in-process route-parity suites load server/startup.js,
 * whose module-level side effects (PostgreSQL pools and monitors, the persistence-recovery worker + journal worker,
 * Redis stores, alerting) were only partly stopped. This runs exactly those suites in a nested
 * `jest --runInBand` with the current PostgreSQL environment and asserts the run EXITS ON ITS OWN, promptly.
 * PostgreSQL-gated (QODIQA_ALLOW_PG_INTEGRATION_TESTS=true + QODIQA_PG_ENABLED=true): without PostgreSQL the recovery
 * queue never starts and the hang cannot occur.
 */

const path = require('path');
const { spawn } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const RUN = process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true' && process.env.QODIQA_PG_ENABLED === 'true';
const SUITES = ['src/openapi/liveRouteParity.test.js', 'src/openapi/conditionalRoutes.test.js', 'src/openapi/mfaStepUpScope.test.js'];
const GRACE_MS = 30_000;   // after Jest prints its summary, the process must be gone within this
const CEILING_MS = 300_000;

(RUN ? describe : describe.skip)('in-process server suites leave nothing running (ER)', () => {
  jest.setTimeout(CEILING_MS + 30_000);

  test('IPS-01 a --runInBand run of the in-process server suites exits on its own after its summary', async () => {
    const r = await new Promise((resolve) => {
      const child = spawn(process.execPath, [path.join(REPO, 'node_modules', 'jest', 'bin', 'jest.js'), '--runInBand', '--ci', ...SUITES],
        { cwd: REPO, env: { ...process.env }, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = ''; let summaryAt = null;
      const onData = (d) => { out += d; if (summaryAt === null && /Ran all test suites/.test(out)) summaryAt = Date.now(); };
      child.stdout.on('data', onData); child.stderr.on('data', onData);
      const tick = setInterval(() => {
        if (summaryAt !== null && Date.now() - summaryAt > GRACE_MS) { clearInterval(tick); child.kill(); resolve({ exited: false, reason: 'alive after summary', out }); }
      }, 500);
      const ceiling = setTimeout(() => { clearInterval(tick); child.kill(); resolve({ exited: false, reason: 'ceiling', out }); }, CEILING_MS);
      child.on('exit', (code) => { clearInterval(tick); clearTimeout(ceiling); resolve({ exited: true, code, afterSummaryMs: summaryAt === null ? null : Date.now() - summaryAt, out }); });
    });
    const tail = r.out.replace(/\x1b\[[0-9;]*m/g, '').split('\n').filter((l) => /^(Tests|Test Suites):/.test(l)).join(' | ');
    expect({ exited: r.exited, reason: r.reason, code: r.code, tail }).toEqual(expect.objectContaining({ exited: true, code: 0 }));
    expect(r.afterSummaryMs).toBeLessThan(GRACE_MS);
  });
});
