'use strict';

/**
 * Regression coverage for FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md §8,
 * prevention layer 2: test/support/jest.setup.js and scripts/performance/lib/setupEnv.js
 * must force QODIQA_PG_ENABLED off for a local, non-CI run unless the
 * developer explicitly opts in — otherwise a QODIQA_PG_ENABLED-gated suite
 * could ambiently see 'true' from .env and write to the real, persistent
 * `qodiqa` database (the exact mechanism that produced 147 orphan rows
 * there, per that report).
 *
 * Each probe spawns a genuinely separate `node` process with a fully
 * controlled environment (not this test process's own, and not relying on
 * whatever ambient .env-loading behavior a plain `npm test` run happens to
 * have) and requires the real guard file directly — this is a test of the
 * actual guard logic, not a simulation of it.
 */

const { execFileSync } = require('child_process');
const path = require('path');

const JEST_SETUP_PATH = path.resolve(__dirname, '..', 'test/support/jest.setup.js');
const PERF_SETUP_ENV_PATH = path.resolve(__dirname, '..', 'scripts', 'performance', 'lib', 'setupEnv.js');
// phase 17: an explicit, DISPOSABLE PostgreSQL target (the pl-env.sh port) — never connected to by these probes.
const EXPLICIT_TARGET = { QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '55510' };

// Starts from this process's own env, then strips every var the guard reads
// so each probe controls exactly the signals it cares about rather than
// inheriting whatever happens to be ambient in the test runner itself.
function probeGuard(setupPath, envOverrides) {
  const env = { ...process.env };
  delete env.CI;
  delete env.QODIQA_ALLOW_PG_INTEGRATION_TESTS;
  delete env.QODIQA_PG_ENABLED;
  Object.assign(env, envOverrides);

  // Both setup files provision a keyStore as a side effect, which logs its
  // own structured JSON lines to stdout (services/logger.js) — a tagged
  // marker line (same convention as test/helpers/audit-chain-distributed-
  // worker.js's WORKER_RESULT:) lets this probe find its own result
  // unambiguously rather than assuming stdout has nothing else on it.
  const out = execFileSync(
    process.execPath,
    [
      '-e',
      `require(${JSON.stringify(setupPath)}); ` +
        `process.stdout.write('PG_ENABLED_RESULT:' + String(process.env.QODIQA_PG_ENABLED) + '\\n');`,
    ],
    { env, encoding: 'utf8', cwd: path.resolve(__dirname, '..') },
  );
  const resultLine = out.split('\n').find((line) => line.startsWith('PG_ENABLED_RESULT:'));
  if (!resultLine) {
    throw new Error(`probeGuard: no PG_ENABLED_RESULT: line found in child output:\n${out}`);
  }
  return resultLine.slice('PG_ENABLED_RESULT:'.length).trim();
}

describe.each([
  ['test/support/jest.setup.js', JEST_SETUP_PATH],
  ['scripts/performance/lib/setupEnv.js', PERF_SETUP_ENV_PATH],
])('%s — PG isolation guard', (_label, setupPath) => {
  test('forces QODIQA_PG_ENABLED to false locally, with no CI and no explicit opt-in, even though it was ambiently true', () => {
    const result = probeGuard(setupPath, { QODIQA_PG_ENABLED: 'true' });
    expect(result).toBe('false');
  });

  test('leaves QODIQA_PG_ENABLED true when CI=true (ephemeral, disposable-per-job container)', () => {
    const result = probeGuard(setupPath, { QODIQA_PG_ENABLED: 'true', CI: 'true' });
    expect(result).toBe('true');
  });

  // phase 17: a local opt-in must also name an explicit, non-LIVE PostgreSQL target (test/support/jest.setup.js refuses it
  // otherwise — see the connection-target block below); a disposable-port target is what pl-env.sh supplies.
  test('leaves QODIQA_PG_ENABLED true with an explicit local opt-in (and an explicit disposable target)', () => {
    const result = probeGuard(setupPath, { QODIQA_PG_ENABLED: 'true', QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', ...EXPLICIT_TARGET });
    expect(result).toBe('true');
  });

  test('never leaves QODIQA_PG_ENABLED=true when it was not explicitly set true in this probe', () => {
    // correction: this assertion's original comment claimed test/support/jest.setup.js
    // leaving the value 'undefined' here was safe ("either outcome is safe").
    // It was not. 'undefined' meant the guard had silently declined to act,
    // and any suite that called require('dotenv').config() ITSELF then pulled
    // QODIQA_PG_ENABLED=true out of .env afterwards and ran against the real
    // database — 306 orphan rows before it was caught. Both setup files now
    // resolve the ambient .env value before deciding, so both force 'false'
    // here; the dedicated block below pins that explicitly rather than
    // relying on this weaker not-'true' assertion.
    const result = probeGuard(setupPath, {});
    expect(result).not.toBe('true');
  });
});

// ── the guard must resolve .env's value, not just process.env's ─────────
// setupFiles runs before any test file and nothing in the jest bootstrap loads
// dotenv, so QODIQA_PG_ENABLED was `undefined` at guard time and the guard's
// own condition was always false — for six days, across 81 gate runs. These
// probes pass NO QODIQA_PG_ENABLED at all (probeGuard strips it), which is
// exactly the real-world shape: ambient only in .env, absent from the
// environment jest actually starts with.
describe('test/support/jest.setup.js — ordering fix (ambient value lives only in .env)', () => {
  // a fixture .env (QODIQA_PG_ENABLED=true) via jest.setup's QODIQA_TEST_DOTENV_PATH hook, instead
  // of whatever the developer's own .env holds — a clean checkout / CI runner has none, and these probes then failed.
  const FIXTURE_ENV = require('path').join(require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'pg-guard-env-')), '.env');
  require('fs').writeFileSync(FIXTURE_ENV, 'QODIQA_PG_ENABLED=true\n');
  const FX = { QODIQA_TEST_DOTENV_PATH: FIXTURE_ENV };

  test('forces false when QODIQA_PG_ENABLED is absent from the environment but true in .env', () => {
    expect(probeGuard(JEST_SETUP_PATH, { ...FX })).toBe('false');
  });

  // The guard only INSPECTS .env, it never applies it — importing .env
  // globally from setupFiles would change what every other suite sees. So when
  // the guard stands aside (CI, or an explicit opt-in) it leaves the variable
  // exactly as it found it: absent. The value only becomes 'true' once the
  // suite itself calls dotenv.config(), which is the real end state worth
  // asserting, so these probes replicate that second step.
  function probeGuardThenDotenv(envOverrides) {
    const env = { ...process.env };
    delete env.CI;
    delete env.QODIQA_ALLOW_PG_INTEGRATION_TESTS;
    delete env.QODIQA_PG_ENABLED;
    Object.assign(env, FX, envOverrides);

    const out = execFileSync(
      process.execPath,
      [
        '-e',
        `require(${JSON.stringify(JEST_SETUP_PATH)}); ` +
          "require('dotenv').config({ path: process.env.QODIQA_TEST_DOTENV_PATH }); " +
          "process.stdout.write('PG_ENABLED_RESULT:' + String(process.env.QODIQA_PG_ENABLED) + '\\n');",
      ],
      { env, encoding: 'utf8', cwd: path.resolve(__dirname, '..') },
    );
    const line = out.split('\n').find((l) => l.startsWith('PG_ENABLED_RESULT:'));
    if (!line) throw new Error(`probeGuardThenDotenv: no result line in:\n${out}`);
    return line.slice('PG_ENABLED_RESULT:'.length).trim();
  }

  test('stands aside under CI=true, so the suite\'s own dotenv.config() still yields true', () => {
    expect(probeGuard(JEST_SETUP_PATH, { ...FX, CI: 'true' })).toBe('undefined');
    expect(probeGuardThenDotenv({ CI: 'true' })).toBe('true');
  });

  // phase 17 (deliberate behaviour change): an opted-in LOCAL run no longer takes QODIQA_PG_ENABLED from .env
  // either — .env is never a test input for PostgreSQL in any local run. The opt-in now needs an explicit target AND an
  // explicit QODIQA_PG_ENABLED=true (pl-env.sh sets both); with only .env's value the flag is pinned 'false', which a
  // later dotenv.config() cannot undo. (Before: 'undefined', then 'true' from the suite's own dotenv load.)
  test('under an explicit local opt-in, .env\'s value is NOT used: pinned false, dotenv cannot resurrect it', () => {
    expect(probeGuard(JEST_SETUP_PATH, { ...FX, QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', ...EXPLICIT_TARGET })).toBe('false');
    expect(probeGuardThenDotenv({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', ...EXPLICIT_TARGET })).toBe('false');
  });
  test('under an explicit local opt-in, an explicit QODIQA_PG_ENABLED=true is kept', () => {
    expect(probeGuardThenDotenv({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', QODIQA_PG_ENABLED: 'true', ...EXPLICIT_TARGET })).toBe('true');
  });

  test('a suite calling dotenv.config() after the guard cannot resurrect true', () => {
    // The precise defect this closes: the guard SETS the variable to 'false',
    // and dotenv never overrides an already-set process.env value — so a test
    // file's own later dotenv.config() is a no-op for this key. Without that
    // explicit set, .env would win, which is exactly what happened for 81 runs.
    expect(probeGuardThenDotenv({})).toBe('false');
  });
});

// ── 2026-10-06: connection-target isolation ─────────────────────────
// A suite that loads .env itself and builds its OWN connection from QODIQA_PG_HOST/PORT/URL bypassed the flag guard above
// (test/dr/postgresFullCoverage did, and reached the cluster hosting LIVE). Without the opt-in, jest.setup pre-sets every
// connection-target key that .env defines to '' so a later dotenv.config() cannot backfill it; the process env still wins.
describe('test/support/jest.setup.js — connection-target keys from .env cannot reach a suite without the opt-in', () => {
  const fs = require('fs'); const os = require('os');
  const FIXTURE_ENV = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pg-guard-target-')), '.env');
  fs.writeFileSync(FIXTURE_ENV, 'QODIQA_PG_HOST=127.0.0.1\nQODIQA_PG_PORT=5432\nQODIQA_PG_URL=postgres://u:p@127.0.0.1:5432/qodiqa\nQODIQA_PG_ENABLED=true\n');

  function probeTarget(envOverrides) {
    const env = { ...process.env };
    for (const k of ['CI', 'QODIQA_ALLOW_PG_INTEGRATION_TESTS', 'QODIQA_PG_ENABLED', 'QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_URL', 'DATABASE_URL', 'PGHOST', 'PGPORT']) delete env[k];
    Object.assign(env, { QODIQA_TEST_DOTENV_PATH: FIXTURE_ENV }, envOverrides);
    const out = execFileSync(process.execPath, ['-e',
      `require(${JSON.stringify(JEST_SETUP_PATH)}); require('dotenv').config({ path: process.env.QODIQA_TEST_DOTENV_PATH }); ` +
      "process.stdout.write('TARGET_RESULT:' + JSON.stringify({ host: process.env.QODIQA_PG_HOST, port: process.env.QODIQA_PG_PORT, url: process.env.QODIQA_PG_URL }) + '\\n');"],
      { env, encoding: 'utf8', cwd: path.resolve(__dirname, '..') });
    const line = out.split('\n').find((l) => l.startsWith('TARGET_RESULT:'));
    if (!line) throw new Error(`probeTarget: no result line in:\n${out}`);
    return JSON.parse(line.slice('TARGET_RESULT:'.length));
  }

  test('no opt-in: a suite-level dotenv.config() gets EMPTY connection targets, not .env\'s cluster', () => {
    expect(probeTarget({})).toEqual({ host: '', port: '', url: '' });
  });
  test('an explicit process-env target (a gate runner\'s disposable cluster) still wins', () => {
    expect(probeTarget({ QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '55510' })).toEqual({ host: '127.0.0.1', port: '55510', url: '' });
  });
  // phase 17 (deliberate behaviour change; before: an opted-in local run took its target from .env).
  test('CI: unchanged — .env still supplies the target (ephemeral service containers)', () => {
    expect(probeTarget({ CI: 'true' }).host).toBe('127.0.0.1');
  });
  function probeRefusal(envOverrides) {
    const env = { ...process.env };
    for (const k of ['CI', 'QODIQA_ALLOW_PG_INTEGRATION_TESTS', 'QODIQA_PG_ENABLED', 'QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_URL', 'DATABASE_URL', 'PGHOST', 'PGPORT', 'REDIS_URL', 'QODIQA_TEST_ALLOW_LIVE_PORTS']) delete env[k];
    Object.assign(env, { QODIQA_TEST_DOTENV_PATH: FIXTURE_ENV }, envOverrides);
    const r = require('child_process').spawnSync(process.execPath, ['-e', `require(${JSON.stringify(JEST_SETUP_PATH)}); process.stdout.write('SETUP_OK\\n');`],
      { env, encoding: 'utf8', cwd: path.resolve(__dirname, '..') });
    return { ok: r.status === 0 && /SETUP_OK/.test(r.stdout), stderr: r.stderr || '' };
  }
  test('opted in locally WITHOUT an explicit target: refused before any suite runs (never .env\'s cluster)', () => {
    const r = probeRefusal({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true' });
    expect(r.ok).toBe(false);
    expect(r.stderr).toMatch(/refusing a local PostgreSQL-integration run: .*no explicit PostgreSQL target/);
  });
  test('opted in locally with an explicit target on a LIVE port (127.0.0.1:5432 / REDIS_URL :6379): refused', () => {
    const pg = probeRefusal({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '5432' });
    expect(pg.ok).toBe(false);
    expect(pg.stderr).toMatch(/127\.0\.0\.1:5432 is a LIVE port/);
    const url = probeRefusal({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', ...EXPLICIT_TARGET, QODIQA_PG_URL: 'postgres://u:p@localhost:5432/x' });
    expect(url.ok).toBe(false);
    expect(url.stderr).toMatch(/QODIQA_PG_URL names localhost:5432/);
    const redis = probeRefusal({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', ...EXPLICIT_TARGET, REDIS_URL: 'redis://localhost:6379' });
    expect(redis.ok).toBe(false);
    expect(redis.stderr).toMatch(/REDIS_URL localhost:6379 is a LIVE port/);
  });
  test('opted in locally with an explicit disposable target: accepted; that target wins and .env cannot back-fill the rest', () => {
    expect(probeRefusal({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', ...EXPLICIT_TARGET }).ok).toBe(true);
    expect(probeTarget({ QODIQA_ALLOW_PG_INTEGRATION_TESTS: 'true', ...EXPLICIT_TARGET })).toEqual({ host: '127.0.0.1', port: '55510', url: '' });
  });
});
