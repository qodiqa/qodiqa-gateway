'use strict';

/**
 * the evaluation harness and its floors.
 *   EV-01  Wilson intervals are right (known values) and the corpus is deterministic and secret-free
 *   EV-02  no figure is reported without an interval and a sample size
 *   EV-03  floors on the corpus (lower bounds of the intervals, not point estimates), so a detector regression fails the build
 */

const { wilson, evaluate, toMarkdown } = require('../eval/evaluate');
const { generate } = require('../eval/corpus');

describe('EV-01 harness', () => {
  test('Wilson interval against known values', () => {
    const w = wilson(50, 100); expect(w.p).toBe(0.5); expect(w.lo).toBeCloseTo(0.4038, 3); expect(w.hi).toBeCloseTo(0.5962, 3);
    const z = wilson(0, 50); expect(z.lo).toBe(0); expect(z.hi).toBeCloseTo(0.0713, 3);
    const o = wilson(50, 50); expect(o.hi).toBeCloseTo(1, 10); expect(o.lo).toBeCloseTo(0.9287, 3);
    expect(wilson(0, 0)).toEqual({ p: null, lo: null, hi: null, n: 0 });
  });
  test('the corpus is deterministic for a seed and different for another', () => {
    const a = generate({ seed: 1, perLanguage: 3 }); const b = generate({ seed: 1, perLanguage: 3 }); const c = generate({ seed: 2, perLanguage: 3 });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b)); expect(JSON.stringify(a)).not.toBe(JSON.stringify(c));
    expect(a.docs.some((d) => d.slice === 'negative')).toBe(true);
    for (const d of a.docs) for (const l of d.labels) expect(d.text.slice(l.start, l.end).length).toBe(l.end - l.start);
  });
});

describe('EV-02 no bare figures', () => {
  const rep = evaluate({ seed: 7, perLanguage: 6 });
  const md = toMarkdown(rep);
  test('every percentage in the report is followed by its interval and sample size', () => {
    const lines = md.split('\n').filter((l) => /\d%/.test(l) && !/Wilson score interval/.test(l));
    expect(lines.length).toBeGreaterThan(10);
    for (const l of lines) {
      const pcts = l.match(/\d+(\.\d+)?%/g) || [];
      const withInterval = l.match(/\d+(\.\d+)?% \[\d+(\.\d+)?, \d+(\.\d+)?\] \(n=\d+\)/g) || [];
      expect(withInterval.length).toBeGreaterThanOrEqual(1);
      // every point estimate has its own interval (the numbers inside the brackets carry no % sign, so they are not counted as figures)
      expect(pcts.length).toBe(withInterval.length);
    }
  });
  test('a rule with few examples says so', () => { expect(md).toMatch(/few examples/); });
});

describe('EV-03 floors (lower bounds of the 95% intervals)', () => {
  const rep = evaluate({ seed: 20261022, perLanguage: 40 });
  test('any-rule recall: a labelled value is almost never missed entirely, in every slice including the evasion slice', () => {
    expect(rep.ruleAgnosticRecall.lo).toBeGreaterThan(0.99);
    expect(rep.slices.evasion.recall.lo).toBeGreaterThan(0.98);
    expect(rep.slices.separators.recall.lo).toBeGreaterThan(0.98);
  });
  test('rule-exact recall for the checksum-validated high-confidence rules', () => {
    for (const r of ['EMAIL', 'CARD', 'IBAN', 'JWT', 'PEM_BLOCK', 'US_SSN', 'CNP', 'KEY_GITHUB', 'KEY_AWS_ACCESS']) expect(rep.rules[r].recall.lo).toBeGreaterThan(0.85);
  });
  test('at minConfidence 0.6 the false-positive document rate on look-alikes is low and precision is high', () => {
    const p = rep.operatingPoints.find((x) => x.minConfidence === 0.6);
    expect(p.falsePositiveDocumentRate.hi).toBeLessThan(0.03); expect(p.precision.lo).toBeGreaterThan(0.99);
  });
  test('the weak spots are in the report, not hidden: PHONE at the permissive setting and the uncovered national ids', () => {
    expect(rep.rules.PHONE.precision.hi).toBeLessThan(0.9);
    expect(rep.uncovered.kinds).toEqual(expect.arrayContaining(['FR_NIR', 'IT_CODICE_FISCALE']));
    expect(rep.markings.neutralTextsFlagged.p).toBeGreaterThan(0);                 // known marking false positives are reported
  });
});
