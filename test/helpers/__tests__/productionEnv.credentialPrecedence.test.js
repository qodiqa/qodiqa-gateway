'use strict';

/**
 * ER — test/helpers/productionEnv.js credential handling, from the coverage-run failure of
 * test/evidenceDurabilityStartupGate.test.js ("productionEnv self-check: unexpected fatal violations:
 * QODIQA_PG_MIG_PASSWORD").
 *
 *   PE-01 explicit process values WIN over .env for the PostgreSQL target (the reverse could point a spawned child at
 *         the .env cluster — which hosts LIVE on the dev machine — while the suite targeted another cluster).
 *   PE-02 an explicit WEAK credential (CI's `qodiqa` migration password) or a published placeholder is replaced by a
 *         strong stand-in, judged by the production validator's OWN rule, so the generated env passes the real
 *         validator — the case CI (no .env) always hit and the dev machine masked.
 *   PE-03 an explicit STRONG credential is passed through verbatim (suites that really connect rely on it).
 *   PE-04 the production validator itself is NOT weakened: the same weak value in a production env is still fatal.
 * PE-05: the migration credential is never handed to a production gateway child, even when the
 *         parent process has it, and a production env that does carry it is refused.
 * (Since the example credential for PE-02..04 is the system-role password: the migration password is no
 *   longer part of a gateway environment.)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { validProductionEnv, assertBootValid } = require('../productionEnv');
const { validateBoot } = require('../../../src/infra/config/bootValidator');
const { secretProblems } = require('../../../src/infra/config/credentialRules');

const KEYS = ['QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PG_MIG_USER', 'QODIQA_PG_MIG_PASSWORD',
  'QODIQA_PG_RETENTION_PASSWORD', 'QODIQA_PG_SYSTEM_PASSWORD', 'QODIQA_PG_REPORTING_PASSWORD', 'QODIQA_PG_CONTROL_PASSWORD', 'QODIQA_PG_BACKUP_PASSWORD'];
let saved; let keysPath;
beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  keysPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pe-')), 'keys.json');
});
afterEach(() => { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

const STRONG = 'a3f9c2e17b8d4c6f9e1a2b3c4d5e6f70';
const ciEnv = () => Object.assign(process.env, {
  QODIQA_PG_HOST: '10.200.30.40', QODIQA_PG_PORT: '55999', QODIQA_PG_USER: 'qodiqa_app', QODIQA_PG_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_APP',
  QODIQA_PG_MIG_USER: 'qodiqa', QODIQA_PG_MIG_PASSWORD: 'qodiqa', QODIQA_PG_RETENTION_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_RETENTION',
  QODIQA_PG_SYSTEM_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_SYSTEM', QODIQA_PG_REPORTING_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_REPORTING',
  QODIQA_PG_CONTROL_PASSWORD: 'REPLACE_WITH_VAULT_SECRET_CONTROL',
});

describe('productionEnv credential precedence and strength (ER)', () => {
  test('PE-01 explicit process values win over .env for the PostgreSQL target', () => {
    ciEnv();
    const env = validProductionEnv({ keysPath, pg: true });
    expect(env.QODIQA_PG_HOST).toBe('10.200.30.40');
    expect(env.QODIQA_PG_PORT).toBe('55999');
    expect(env.QODIQA_PG_USER).toBe('qodiqa_app');
  });

  test('PE-02 weak or placeholder explicit credentials become strong stand-ins; the env passes the REAL production validator', () => {
    ciEnv();
    const env = validProductionEnv({ keysPath, pg: true });
    // exactly the credentials ciEnv() set explicitly (BACKUP is not a pool credential here and is blanked by the helper)
    for (const k of ['QODIQA_PG_PASSWORD', 'QODIQA_PG_RETENTION_PASSWORD', 'QODIQA_PG_SYSTEM_PASSWORD', 'QODIQA_PG_REPORTING_PASSWORD', 'QODIQA_PG_CONTROL_PASSWORD']) {
      expect(secretProblems(env[k], { minLength: 16 })).toEqual([]);
      expect(env[k]).not.toBe(process.env[k]);
    }
    expect(() => assertBootValid(env)).not.toThrow();
  });

  test('PE-03 an explicit strong credential is passed through verbatim', () => {
    ciEnv();
    process.env.QODIQA_PG_SYSTEM_PASSWORD = STRONG;
    const env = validProductionEnv({ keysPath, pg: true });
    expect(env.QODIQA_PG_SYSTEM_PASSWORD).toBe(STRONG);
  });

  test('PE-04 the production validator is not weakened: the weak CI value in a production env is still fatal', () => {
    ciEnv();
    const env = validProductionEnv({ keysPath, pg: true, overrides: { QODIQA_PG_SYSTEM_PASSWORD: 'qodiqa' } });
    const r = validateBoot(env);
    expect(r.fatal.map((f) => f.variable)).toContain('QODIQA_PG_SYSTEM_PASSWORD');
    expect(() => assertBootValid(env)).toThrow(/QODIQA_PG_SYSTEM_PASSWORD/);
  });

  test('PE-05 the migration credential never reaches a production gateway child; carrying it is refused', () => {
    ciEnv();
    process.env.QODIQA_PG_MIG_PASSWORD = STRONG;
    const env = validProductionEnv({ keysPath, pg: true });
    expect(env.QODIQA_PG_MIG_PASSWORD).toBe('');
    expect(env.QODIQA_PG_MIG_USER).toBe('');
    expect(() => assertBootValid(env)).not.toThrow();
    const carrying = validProductionEnv({ keysPath, pg: true, overrides: { QODIQA_PG_MIG_PASSWORD: STRONG } });
    expect(validateBoot(carrying).fatal.map((f) => f.variable)).toContain('QODIQA_PG_MIG_PASSWORD');
  });
});
