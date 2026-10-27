'use strict';

// this suite exercises the embedding gate with a stand-in classifier
process.env.QODIQA_SEM_EMBEDDING_ENABLED = 'true';

/**
 * FT-2 MONITORING CONTRACT
 *
 * The fifth gate was enabled in production on 2026-08-18 on the condition that
 * three monitoring surfaces shipped with it. This suite is what makes that
 * condition enforceable rather than aspirational:
 *
 *   1. SEM_FT2_CONSULTED       one structured event per CONSULTED request, and
 *                              silence below the band (the band is also the
 *                              reaches the second model, and must not log).
 *                              in EITHER direction. A collapse toward zero is a
 *                              silently-broken band and matters as much as a
 *                              spike.
 *   3. SEM_FT2_SCORING_FAILED  CRITICAL, distinct from the generic infra-failure
 *                              path, because FT-2 is FAIL-CLOSED: a model fault
 *                              turns every eligible request into a DENY. That is
 *                              correct behaviour and the loudest thing the
 *                              system can do, so it must be visible as a denial
 *                              storm rather than buried.
 *
 * The gate is mocked at the classifier boundary throughout. These are assertions
 * about the OBSERVABILITY CONTRACT, not about detection — detection is measured
 * end-to-end elsewhere, and a monitoring test that needed the real 90 MB model
 * would be too slow to keep.
 */

const path = require('path');

const GATE = path.join(__dirname, '..', 'embeddingGate.js');
const CLASSIFIER = path.join(__dirname, '..', 'embeddingSimilarity');
const LOGGER = path.join(__dirname, '..', '..', '..', '..', 'services', 'logger');
const METRICS = path.join(__dirname, '..', '..', '..', 'observability', 'metrics');

function baseResult(over = {}) {
  return {
    decision: 'ALLOW',
    score: 0.31,
    threshold: 0.48,
    matchedAnchorId: null,
    headScore: 0.1,
    headFired: false,
    v9Score: 0.1,
    v9Fired: false,
    v5Score: 0.1,
    v5Fired: false,
    matchedBy: null,
    engineStatus: 'READY',
    failureReason: null,
    ...over,
  };
}

function load(classifyImpl, { ft2Enabled = true } = {}) {
  jest.resetModules();
  // The rate band only applies while FT-2 is enabled; these tests are about the enabled case.
  process.env.QODIQA_SEM_FT2_ENABLED = ft2Enabled ? 'true' : 'false';
  jest.doMock(CLASSIFIER, () => ({ classify: classifyImpl, init: jest.fn(), getStatus: jest.fn() }));
  const emit = jest.fn();
  jest.doMock(LOGGER, () => ({ emit }));
  // eslint-disable-next-line global-require
  const metrics = require(METRICS);
  // eslint-disable-next-line global-require
  const gate = require(GATE);
  gate._resetFt2RateForTests();
  return { gate, emit, metrics };
}

describe('FT-2 monitoring — SEM_FT2_CONSULTED', () => {
  it('emits exactly one structured event when the gate was consulted', async () => {
    const { gate, emit } = load(async () => baseResult({
      ft2Consulted: true, ft2Score: -0.02, ft2Fired: false, ft2Family: 'literal',
    }));
    await gate.checkText('some prompt', { requestId: 'r-1', tenantId: 't-1', provider: 'openai' });

    const consulted = emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_CONSULTED');
    expect(consulted).toHaveLength(1);
    const [level, , payload] = consulted[0];
    expect(level).toBe('INFO');
    expect(payload).toMatchObject({
      requestId: 'r-1', tenantId: 't-1', provider: 'openai',
      anchorScore: 0.31, ft2Score: -0.02, ft2Family: 'literal',
      fired: false, verdict: 'ALLOW',
    });
  });

  it('reports verdict DENY and fired=true when the fifth gate is what denied', async () => {
    const { gate, emit } = load(async () => baseResult({
      decision: 'DENY', matchedBy: 'ft2',
      ft2Consulted: true, ft2Score: 0.05, ft2Fired: true, ft2Family: 'confidential_org_information',
    }));
    const out = await gate.checkText('some prompt', { requestId: 'r-2' });
    expect(out.blocks).toBe(true);

    const [, , payload] = emit.mock.calls.find((c) => c[1] === 'SEM_FT2_CONSULTED');
    expect(payload).toMatchObject({ fired: true, verdict: 'DENY', ft2Family: 'confidential_org_information' });
  });

  it('IS SILENT below the band — the band is the noise control', async () => {
    // No ft2Consulted key at all: this is what a below-band or flag-off result
    // looks like, and it must produce no per-request log line.
    const { gate, emit } = load(async () => baseResult({ score: 0.11 }));
    for (let i = 0; i < 25; i++) await gate.checkText('benign', { requestId: `r-${i}` });
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_CONSULTED')).toHaveLength(0);
  });
});

describe('FT-2 monitoring — invocation rate', () => {
  /** Drives n requests of which `consultedEvery`-th is consulted. */
  async function drive(gate, n, isConsulted) {
    for (let i = 0; i < n; i++) {
      // eslint-disable-next-line no-await-in-loop
      await gate.checkText(`p-${i}`, { requestId: `r-${i}`, _i: i });
    }
    return isConsulted;
  }

  it('stays quiet below the minimum sample — a cold process must not alert', async () => {
    let i = 0;
    const { gate, emit } = load(async () => baseResult(i++ % 4 === 0
      ? { ft2Consulted: true, ft2Score: -0.1, ft2Fired: false } : {}));
    await drive(gate, 150);
    expect(emit.mock.calls.filter((c) => String(c[1]).startsWith('SEM_FT2_RATE'))).toHaveLength(0);
  });

  it('reports IN-BAND at the measured ~24% rate without warning', async () => {
    let i = 0;
    const { gate, emit } = load(async () => baseResult(i++ % 4 === 0
      ? { ft2Consulted: true, ft2Score: -0.1, ft2Fired: false } : {}));
    await drive(gate, 400);
    const rate = emit.mock.calls.filter((c) => String(c[1]).startsWith('SEM_FT2_RATE'));
    expect(rate.length).toBeGreaterThan(0);
    for (const [level, event, payload] of rate) {
      expect(event).toBe('SEM_FT2_RATE');
      expect(level).toBe('INFO');
      expect(payload.rate).toBeCloseTo(0.25, 2);
      expect(payload.band).toEqual([0.14, 0.34]);
    }
  });

  it('WARNS when the rate runs ABOVE the band — attack-shaped traffic or band drift', async () => {
    // or above that is the signal worth waking someone for.
    const { gate, emit } = load(async () => baseResult({ ft2Consulted: true, ft2Score: -0.1, ft2Fired: false }));
    await drive(gate, 400);
    const warns = emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_RATE_OUT_OF_BAND');
    expect(warns.length).toBeGreaterThan(0);
    expect(warns[0][0]).toBe('WARN');
    expect(warns[0][2].direction).toBe('ABOVE');
    expect(warns[0][2].rate).toBe(1);
  });

  it('WARNS when the rate COLLAPSES below the band — a silently-broken band', async () => {
    // This is the direction that would otherwise look like good news: the gate
    // has quietly stopped being consulted and the system is cheaper than
    // expected, while detection has silently reverted to four gates.
    const { gate, emit } = load(async () => baseResult({ score: 0.05 }));
    await drive(gate, 400);
    const warns = emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_RATE_OUT_OF_BAND');
    expect(warns.length).toBeGreaterThan(0);
    expect(warns[0][2].direction).toBe('BELOW');
    expect(warns[0][2].rate).toBe(0);
  });
});

describe('FT-2 monitoring — FT2_SCORING_FAILED is CRITICAL and fail-closed', () => {
  for (const reason of ['FT2_SCORING_FAILED', 'FT2_SCORING_PRODUCED_NON_FINITE_RESULT']) {
    it(`emits CRITICAL and denies on ${reason}`, async () => {
      const { gate, emit } = load(async () => baseResult({
        decision: 'DENY', engineStatus: 'UNAVAILABLE', failureReason: reason, score: null,
      }));
      const out = await gate.checkText('anything', { requestId: 'r-9', tenantId: 't-9' });

      // fail-closed: the request is denied
      expect(out.blocks).toBe(true);
      expect(out.decision).toBe('DENY');

      const crit = emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_SCORING_FAILED');
      expect(crit).toHaveLength(1);
      expect(crit[0][0]).toBe('CRITICAL');
      expect(crit[0][2]).toMatchObject({ requestId: 'r-9', tenantId: 't-9', reason });
      expect(crit[0][2].impact).toMatch(/FAIL_CLOSED_DENY/);
    });
  }

  it('does NOT fire the FT-2 alert for unrelated engine failures', async () => {
    const { gate, emit } = load(async () => baseResult({
      decision: 'DENY', engineStatus: 'UNAVAILABLE', failureReason: 'EMBEDDING_INFERENCE_FAILED', score: null,
    }));
    await gate.checkText('anything', { requestId: 'r-10' });
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_SCORING_FAILED')).toHaveLength(0);
  });

  it('does not count a failed evaluation toward the invocation rate', async () => {
    // A denial storm must not also corrupt the rate signal an operator is using
    // to diagnose it.
    const { gate, emit } = load(async () => baseResult({
      decision: 'DENY', engineStatus: 'UNAVAILABLE', failureReason: 'FT2_SCORING_FAILED', score: null,
    }));
    for (let i = 0; i < 400; i++) await gate.checkText('x', { requestId: `r-${i}` });
    expect(emit.mock.calls.filter((c) => String(c[1]).startsWith('SEM_FT2_RATE'))).toHaveLength(0);
  });
});

describe('FT-2 monitoring — no false rate alarm while FT-2 is disabled', () => {
  afterEach(() => { delete process.env.QODIQA_SEM_FT2_ENABLED; });

  test('FT-2 off: 1,000 eligible requests and zero consultations emit no SEM_FT2_RATE* event', async () => {
    const { gate, emit } = load(async () => baseResult(), { ft2Enabled: false });
    for (let i = 0; i < 1000; i++) await gate.checkText('x', {});
    expect(emit.mock.calls.filter((c) => String(c[1]).startsWith('SEM_FT2_RATE'))).toHaveLength(0);
  });

  test('FT-2 on: the same traffic DOES warn (a collapsed band is still detected when it matters)', async () => {
    const { gate, emit } = load(async () => baseResult(), { ft2Enabled: true });
    for (let i = 0; i < 1000; i++) await gate.checkText('x', {});
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_RATE_OUT_OF_BAND').length).toBeGreaterThan(0);
  });
});
