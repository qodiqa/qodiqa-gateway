'use strict';

/**
 * QODIQA_AUDIT_MIRROR_RECOVERY_MODE / QODIQA_AUDIT_VERIFIER_RECOVERY_MODE downgrade the FATAL boot
 * integrity gates to WARN. Before this rule the boot validator did not mention them at all, so a production deployment
 * could carry either switch indefinitely. Production now refuses them unless QODIQA_AUDIT_RECOVERY_MODE_UNTIL is an
 * ISO-8601 time in the future and at most 24 h ahead.
 */

const { validateBoot } = require('../bootValidator');
const { generate } = require('../../../../scripts/config/generate-boot-rules-doc');

const SWITCHES = ['QODIQA_AUDIT_MIRROR_RECOVERY_MODE', 'QODIQA_AUDIT_VERIFIER_RECOVERY_MODE'];

describe('audit-integrity recovery switches are guarded in production', () => {
  const findings = (env) => {
    const r = validateBoot(env);
    return { fatal: r.fatal.map((f) => f.variable), warnings: r.warnings.map((f) => f.variable) };
  };

  // Use the generator's own probe machinery: a probe row exists per switch and must render "refuse" in production.
  test('the generated boot-rules table refuses each switch in production and warns elsewhere', () => {
    const doc = generate();
    for (const n of SWITCHES) {
      const row = doc.split('\n').find((l) => l.includes(`\`${n}=true\``));
      expect(row).toBeDefined();
      expect(row).toMatch(/\| \*\*refuse\*\* \| warn \| warn \|/);
    }
  });

  describe.each(SWITCHES)('%s', (n) => {
    const base = { NODE_ENV: 'production' };

    test('production without an acknowledgement → fatal', () => {
      expect(findings({ ...base, [n]: 'true' }).fatal).toContain(n);
    });

    test('production with an acknowledgement in the past → fatal', () => {
      const until = new Date(Date.now() - 60_000).toISOString();
      expect(findings({ ...base, [n]: 'true', QODIQA_AUDIT_RECOVERY_MODE_UNTIL: until }).fatal).toContain(n);
    });

    test('production with an acknowledgement more than 24 h ahead → fatal (cannot be pre-set or left on)', () => {
      const until = new Date(Date.now() + 25 * 3600 * 1000).toISOString();
      expect(findings({ ...base, [n]: 'true', QODIQA_AUDIT_RECOVERY_MODE_UNTIL: until }).fatal).toContain(n);
    });

    test('production with a malformed acknowledgement → fatal', () => {
      expect(findings({ ...base, [n]: 'true', QODIQA_AUDIT_RECOVERY_MODE_UNTIL: 'tomorrow' }).fatal).toContain(n);
    });

    test('production with an acknowledgement within 24 h → not fatal for this switch, but a warning', () => {
      const until = new Date(Date.now() + 2 * 3600 * 1000).toISOString();
      const f = findings({ ...base, [n]: 'true', QODIQA_AUDIT_RECOVERY_MODE_UNTIL: until });
      expect(f.fatal).not.toContain(n);
      expect(f.warnings).toContain(n);
    });

    test('development: a warning, never fatal', () => {
      const f = findings({ NODE_ENV: 'development', [n]: 'true' });
      expect(f.fatal).not.toContain(n);
      expect(f.warnings).toContain(n);
    });

    test('switch unset or false → no finding for it in any profile', () => {
      for (const v of [undefined, 'false']) {
        const env = { ...base }; if (v) env[n] = v;
        const f = findings(env);
        expect(f.fatal).not.toContain(n);
        expect(f.warnings).not.toContain(n);
      }
    });
  });

});
