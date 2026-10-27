'use strict';

// this suite exercises the embedding gate with a stand-in classifier
process.env.QODIQA_SEM_EMBEDDING_ENABLED = 'true';

/**
 * FT-3 MONITORING CONTRACT
 *
 * The SWAP puts FT-3 in the slot FT-2 held: the first fine-tuned
 * gate, consulted when the four cheap gates did not DENY and the max anchor
 * score reaches the 0.2977 grey band. FT-2 stays WIRED BEHIND ITS FLAG so the
 * swap is reversible without a deploy, which is why these surfaces are
 * DUAL-TRACKED rather than re-pointed — ft2Monitoring.test.js still asserts
 * FT-2's three surfaces, and this suite asserts FT-3's.
 *
 * The three surfaces, mirroring the condition FT-2 shipped under:
 *
 *   1. SEM_FT3_CONSULTED       one structured event per CONSULTED request, and
 *                              silence below the band (the band is also the
 *                              noise control — most legitimate traffic never
 *                              reaches the fine-tuned model, and must not log).
 *                              in EITHER direction. A collapse toward zero is a
 *                              silently-broken band and matters as much as a
 *                              spike.
 *   3. SEM_FT3_SCORING_FAILED  CRITICAL, distinct from the generic infra-failure
 *                              path AND from FT-2's, because FT-3 is
 *                              FAIL-CLOSED: a model fault turns every eligible
 *                              request into a DENY. An operator must be able to
 *                              tell WHICH model is producing the denial storm.
 *
 * same `result.score` against the same 0.2977 band from the same position in
 * the chain, so the consultation populations are identical by construction —
 * and measured identical over the recorded sets (ext88 14, 234
 * consultations in both configurations). A second, uncalibrated band would
 * have been a fresh number with no derivation behind it.
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

function load(classifyImpl) {
  jest.resetModules();
  jest.doMock(CLASSIFIER, () => ({ classify: classifyImpl, init: jest.fn(), getStatus: jest.fn() }));
  const emit = jest.fn();
  jest.doMock(LOGGER, () => ({ emit }));
  // eslint-disable-next-line global-require
  const metrics = require(METRICS);
  // eslint-disable-next-line global-require
  const gate = require(GATE);
  gate._resetFt2RateForTests();
  gate._resetFt3RateForTests();
  return { gate, emit, metrics };
}

describe('FT-3 monitoring — SEM_FT3_CONSULTED', () => {
  it('emits exactly one structured event when the gate was consulted', async () => {
    const { gate, emit } = load(async () => baseResult({
      ft3Consulted: true, ft3Score: -0.02, ft3Fired: false, ft3Family: 'literal',
    }));
    await gate.checkText('some prompt', { requestId: 'r-1', tenantId: 't-1', provider: 'openai' });

    const consulted = emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_CONSULTED');
    expect(consulted).toHaveLength(1);
    const [level, , payload] = consulted[0];
    expect(level).toBe('INFO');
    expect(payload).toMatchObject({
      requestId: 'r-1', tenantId: 't-1', provider: 'openai',
      anchorScore: 0.31, ft3Score: -0.02, ft3Family: 'literal',
      fired: false, verdict: 'ALLOW',
    });
  });

  it('reports verdict DENY and fired=true when the fine-tuned gate is what denied', async () => {
    const { gate, emit } = load(async () => baseResult({
      decision: 'DENY', matchedBy: 'ft3',
      ft3Consulted: true, ft3Score: 0.05, ft3Fired: true, ft3Family: 'roleplay',
    }));
    const out = await gate.checkText('some prompt', { requestId: 'r-2' });
    expect(out.blocks).toBe(true);

    const [, , payload] = emit.mock.calls.find((c) => c[1] === 'SEM_FT3_CONSULTED');
    expect(payload).toMatchObject({ fired: true, verdict: 'DENY', ft3Family: 'roleplay' });
  });

  it('IS SILENT below the band — the band is the noise control', async () => {
    // No ft3Consulted key at all: this is what a below-band or flag-off result
    // looks like, and it must produce no per-request log line.
    const { gate, emit } = load(async () => baseResult({ score: 0.11 }));
    for (let i = 0; i < 25; i++) await gate.checkText('benign', { requestId: `r-${i}` });
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_CONSULTED')).toHaveLength(0);
  });

  it('does not emit FT-2 events when only FT-3 ran — the two are independently tracked', async () => {
    const { gate, emit } = load(async () => baseResult({
      ft3Consulted: true, ft3Score: -0.02, ft3Fired: false, ft3Family: 'literal',
    }));
    await gate.checkText('some prompt', { requestId: 'r-3' });
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_CONSULTED')).toHaveLength(0);
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_CONSULTED')).toHaveLength(1);
  });
});

describe('FT-3 monitoring — invocation rate', () => {
  async function drive(gate, n) {
    for (let i = 0; i < n; i++) {
      // eslint-disable-next-line no-await-in-loop
      await gate.checkText(`p-${i}`, { requestId: `r-${i}` });
    }
  }

  it('stays quiet below the minimum sample — a cold process must not alert', async () => {
    let i = 0;
    const { gate, emit } = load(async () => baseResult(i++ % 4 === 0
      ? { ft3Consulted: true, ft3Score: -0.1, ft3Fired: false } : {}));
    await drive(gate, 150);
    expect(emit.mock.calls.filter((c) => String(c[1]).startsWith('SEM_FT3_RATE'))).toHaveLength(0);
  });

  it('reports IN-BAND at the measured ~24% rate without warning', async () => {
    let i = 0;
    const { gate, emit } = load(async () => baseResult(i++ % 4 === 0
      ? { ft3Consulted: true, ft3Score: -0.1, ft3Fired: false } : {}));
    await drive(gate, 400);
    const rate = emit.mock.calls.filter((c) => String(c[1]).startsWith('SEM_FT3_RATE'));
    expect(rate.length).toBeGreaterThan(0);
    for (const [level, event, payload] of rate) {
      expect(event).toBe('SEM_FT3_RATE');
      expect(level).toBe('INFO');
      expect(payload.rate).toBeCloseTo(0.25, 2);
      expect(payload.band).toEqual([0.14, 0.34]);
    }
  });

  it('WARNS when the rate runs ABOVE the band — attack-shaped traffic or band drift', async () => {
    const { gate, emit } = load(async () => baseResult({ ft3Consulted: true, ft3Score: -0.1, ft3Fired: false }));
    await drive(gate, 400);
    const warns = emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_RATE_OUT_OF_BAND');
    expect(warns.length).toBeGreaterThan(0);
    expect(warns[0][0]).toBe('WARN');
    expect(warns[0][2].direction).toBe('ABOVE');
    expect(warns[0][2].rate).toBe(1);
  });

  it('WARNS when the rate COLLAPSES below the band — a silently-broken band', async () => {
    // The direction that would otherwise look like good news: the gate has
    // quietly stopped being consulted and the system is cheaper than expected,
    // while detection has silently reverted to four gates.
    const { gate, emit } = load(async () => baseResult({ score: 0.05 }));
    await drive(gate, 400);
    const warns = emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_RATE_OUT_OF_BAND');
    expect(warns.length).toBeGreaterThan(0);
    expect(warns[0][2].direction).toBe('BELOW');
    expect(warns[0][2].rate).toBe(0);
  });
});

describe('FT-3 monitoring — FT3_SCORING_FAILED is CRITICAL and fail-closed', () => {
  for (const reason of ['FT3_SCORING_FAILED', 'FT3_SCORING_PRODUCED_NON_FINITE_RESULT']) {
    it(`emits CRITICAL and denies on ${reason}`, async () => {
      const { gate, emit } = load(async () => baseResult({
        decision: 'DENY', engineStatus: 'UNAVAILABLE', failureReason: reason, score: null,
      }));
      const out = await gate.checkText('anything', { requestId: 'r-9', tenantId: 't-9' });

      // fail-closed: the request is denied
      expect(out.blocks).toBe(true);
      expect(out.decision).toBe('DENY');

      const crit = emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_SCORING_FAILED');
      expect(crit).toHaveLength(1);
      expect(crit[0][0]).toBe('CRITICAL');
      expect(crit[0][2]).toMatchObject({ requestId: 'r-9', tenantId: 't-9', reason });
      expect(crit[0][2].impact).toMatch(/FAIL_CLOSED_DENY/);
    });
  }

  it('does NOT fire the FT-3 alert for unrelated engine failures', async () => {
    const { gate, emit } = load(async () => baseResult({
      decision: 'DENY', engineStatus: 'UNAVAILABLE', failureReason: 'EMBEDDING_INFERENCE_FAILED', score: null,
    }));
    await gate.checkText('anything', { requestId: 'r-10' });
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_SCORING_FAILED')).toHaveLength(0);
  });

  it('does NOT fire the FT-3 alert for an FT-2 scoring failure, and vice versa', async () => {
    // The whole point of a separate surface: in a reversible swap either model
    // can be the one in the path, and an operator diagnosing a denial storm
    // must not be told the wrong one failed.
    const { gate, emit } = load(async () => baseResult({
      decision: 'DENY', engineStatus: 'UNAVAILABLE', failureReason: 'FT2_SCORING_FAILED', score: null,
    }));
    await gate.checkText('anything', { requestId: 'r-11' });
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT3_SCORING_FAILED')).toHaveLength(0);
    expect(emit.mock.calls.filter((c) => c[1] === 'SEM_FT2_SCORING_FAILED')).toHaveLength(1);
  });

  it('does not count a failed evaluation toward the invocation rate', async () => {
    // A denial storm must not also corrupt the rate signal an operator is using
    // to diagnose it.
    const { gate, emit } = load(async () => baseResult({
      decision: 'DENY', engineStatus: 'UNAVAILABLE', failureReason: 'FT3_SCORING_FAILED', score: null,
    }));
    for (let i = 0; i < 400; i++) await gate.checkText('x', { requestId: `r-${i}` });
    expect(emit.mock.calls.filter((c) => String(c[1]).startsWith('SEM_FT3_RATE'))).toHaveLength(0);
  });
});
