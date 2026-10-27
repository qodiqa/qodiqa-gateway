'use strict';

/**
 * the scoring engine skipped every control that lacks an `enabled` field — and none of the
 * registry's controls defines one — so every report scored 0/100 NON_COMPLIANT with zero controls assessed. The existing
 * unit tests passed because their hand-written controls carried `enabled: true`. These tests use the REAL registry controls.
 */

const { getControlsForFramework, FRAMEWORK_IDS } = require('../controlRegistry');
const { scoreFramework } = require('../scoringEngine');

describe('scoreFramework with the real control registry', () => {
  test.each(FRAMEWORK_IDS)('SC-01 %s: real registry controls are assessed (not skipped for lacking `enabled`)', (fw) => {
    const controls = getControlsForFramework(fw);
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.some((c) => 'enabled' in c)).toBe(false); // the shape that exposed the defect
    const vr = new Map(controls.map((c) => [c.id, { score: 100, findings: [], evidenceCount: 3 }]));
    const out = scoreFramework(controls, vr);
    expect(out.controlScores).toHaveLength(controls.length); // before the fix: 0
    expect(out.frameworkScore).toBe(100);                    // before the fix: always 0
    expect(out.verdict).toBe('COMPLIANT');
  });

  test('SC-02 an explicitly disabled control is still skipped', () => {
    const [c1, c2] = getControlsForFramework(FRAMEWORK_IDS[0]).slice(0, 2).map((c) => ({ ...c }));
    c2.enabled = false;
    const out = scoreFramework([c1, c2], new Map([[c1.id, { score: 90 }], [c2.id, { score: 0 }]]));
    expect(out.controlScores.map((s) => s.controlId)).toEqual([c1.id]);
    expect(out.frameworkScore).toBe(90);
  });

  test('SC-03 a failing critical control still yields a non-compliant outcome (the fix does not turn everything green)', () => {
    const controls = getControlsForFramework(FRAMEWORK_IDS[0]);
    const critical = controls.find((c) => c.isCritical);
    const vr = new Map(controls.map((c) => [c.id, { score: c === critical ? 0 : 100 }]));
    const out = scoreFramework(controls, vr);
    expect(out.criticalFailCount).toBeGreaterThanOrEqual(1);
    expect(out.verdict).not.toBe('COMPLIANT');
  });
});
