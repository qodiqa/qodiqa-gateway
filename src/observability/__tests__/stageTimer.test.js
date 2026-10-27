'use strict';

/**
 * the permanent stage timer (src/observability/stageTimer.js).
 *
 *   ST-01  OFF (the default): every wrapper returns the ORIGINAL function object — the instrumented
 * modules run exactly the code they ran; no AsyncLocalStorage, no ring buffer
 *   ST-02  OFF: the timed references in the instrumented modules are identity (aiChat's policy/
 *          semantic/audit/transparency calls, validateBoundRequest's S18–S21, execution's S28)
 *   ST-03  ON: a request record accumulates sync/async/explicit stages, counts repeats, keeps
 *          nested stages (S24a) separately, and closes on 'finish' with a server total and S36
 *   ST-04  ON: the readout is loopback-only
 * ST-05 the boot validator refuses the flag in production and rejects a malformed value
 */

const { EventEmitter } = require('events');

function load(on) {
  let mod;
  const saved = process.env.QODIQA_BENCH_STAGE_TIMING;
  if (on) process.env.QODIQA_BENCH_STAGE_TIMING = 'true'; else delete process.env.QODIQA_BENCH_STAGE_TIMING;
  jest.isolateModules(() => { mod = require('../stageTimer'); });
  if (saved === undefined) delete process.env.QODIQA_BENCH_STAGE_TIMING; else process.env.QODIQA_BENCH_STAGE_TIMING = saved;
  return mod;
}

function fakeReqRes() {
  const res = new EventEmitter();
  res.statusCode = 200;
  res.json = function json() { return this; };
  const req = { method: 'POST', originalUrl: '/ai/chat?x=1', requestId: 'req-1', socket: { remoteAddress: '127.0.0.1' } };
  return { req, res };
}

describe('stage timer', () => {
  test('ST-01 OFF: wrappers are identity; no per-request machinery exists', () => {
    const ST = load(false);
    expect(ST.ON).toBe(false);
    const f = () => 1; const g = async () => 2; const mw = (req, res, next) => next();
    expect(ST.timeSync('S18', f)).toBe(f);
    expect(ST.timeAsync('S33', g)).toBe(g);
    expect(ST.wrapMiddleware('S01', mw)).toBe(mw);
  });

  test('ST-02 OFF: the instrumented modules keep the original functions', () => {
    delete process.env.QODIQA_BENCH_STAGE_TIMING;
    const exec = require('../../../services/execution');
    const guard = require('../../../services/execution-guard');
    // execution.js binds assertExecutionInvariant at load: with the flag off it must be the guard's own function
    const src = require('fs').readFileSync(require.resolve('../../../services/execution'), 'utf8');
    expect(src).toMatch(/timeSync\('S28', require\('\.\/execution-guard'\)\.assertExecutionInvariant\)/);
    expect(typeof exec.executeProviderCall).toBe('function');
    expect(require('../stageTimer').timeSync('S28', guard.assertExecutionInvariant)).toBe(guard.assertExecutionInvariant);
  });

  test('ST-03 ON: stages accumulate per request; nested stages stay separate; finish closes the record', async () => {
    const ST = load(true);
    expect(ST.ON).toBe(true);
    const { req, res } = fakeReqRes();
    const busy = (ms) => { const t = process.hrtime.bigint(); while (Number(process.hrtime.bigint() - t) / 1e6 < ms) { /* spin */ } };
    await new Promise((resolve) => {
      ST.requestMiddleware(req, res, async () => {
        ST.timeSync('S18', () => busy(3))();
        await ST.timeAsync('S24', async () => { await ST.timeAsync('S24a', async () => busy(2))(); busy(1); })();
        ST.timeSync('S21', () => busy(1))();
        ST.timeSync('S21', () => busy(1))();
        ST.add('S30', 5);
        ST.mark('first_content_forwarded');
        ST.label('stream', false);
        res.json({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' });
        res.emit('finish');
        resolve();
      });
    });
    const router = ST.benchRouter();
    const get = router.stack.find((l) => l.route && l.route.path === '/' && l.route.methods.get).route.stack[1].handle;
    let body;
    get({ query: {}, socket: { remoteAddress: '127.0.0.1' } }, { json: (b) => { body = b; } });
    expect(body.records).toHaveLength(1);
    const r = body.records[0];
    expect(r.path).toBe('/ai/chat');
    expect(r.requestId).toBe('req-1');
    expect(r.labels).toMatchObject({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', stream: false });
    expect(r.counts.S21).toBe(2);
    expect(r.stages.S18).toBeGreaterThanOrEqual(2.5);
    expect(r.stages.S24a).toBeGreaterThanOrEqual(1.5);
    expect(r.stages.S24).toBeGreaterThan(r.stages.S24a);
    expect(r.stages.S30).toBe(5);
    expect(r.stages.S36).toBeGreaterThanOrEqual(0);
    expect(r.totalMs).toBeGreaterThanOrEqual(r.stages.S18 + r.stages.S24 + r.stages.S21);
    expect(body.stages.S24a.parent).toBe('S24');
  });

  test('ST-04 ON: the readout answers loopback only', () => {
    const ST = load(true);
    const route = ST.benchRouter().stack.find((l) => l.route && l.route.methods.get).route;
    const loopbackOnly = route.stack[0].handle;
    let status = null; let passed = false;
    loopbackOnly({ socket: { remoteAddress: '10.0.0.5' } }, { status: (s) => { status = s; return { end: () => {} }; } }, () => { passed = true; });
    expect({ status, passed }).toEqual({ status: 404, passed: false });
    loopbackOnly({ socket: { remoteAddress: '::1' } }, {}, () => { passed = true; });
    expect(passed).toBe(true);
  });

  test('ST-05 boot validator: refused in production; malformed value refused everywhere', () => {
    const { validateBoot } = require('../../infra/config/bootValidator');
    const bench = (env) => validateBoot(env).fatal.filter((f) => f.rule === 'bench.stage_timing').map((f) => f.message);
    expect(bench({ NODE_ENV: 'production', QODIQA_BENCH_STAGE_TIMING: 'true' })).toEqual(['QODIQA_BENCH_STAGE_TIMING: the bench stage timer is refused in production']);
    expect(bench({ NODE_ENV: 'production', QODIQA_BENCH_STAGE_TIMING: 'false' })).toEqual([]);
    expect(bench({ NODE_ENV: 'development', QODIQA_BENCH_STAGE_TIMING: 'true' })).toEqual([]);
    expect(bench({ NODE_ENV: 'development', QODIQA_BENCH_STAGE_TIMING: 'yes' })).toEqual(["QODIQA_BENCH_STAGE_TIMING: must be 'true' or 'false'"]);
  });
});
