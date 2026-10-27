'use strict';

/**
 * regression coverage — scripts/lib/bootstrapIsolationGuard.js.
 *
 * This is FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md §8 prevention layer 2
 * extended to the `npm run dev` entry point, so it is tested in the same
 * spirit as test/pgIsolationGuard.test.js already tests layer 2 for the test
 * entry points: against the real guard module, not a simulation of it.
 *
 * The two incidents this guard exists to prevent ('s POLICY_FILE leak,'s
 * dotenv backfill of QODIQA_PG_DATABASE) both wrote to shared state BEFORE any
 * existing check ran, so the assertions below deliberately pin the guard's
 * refusal semantics and its fatal-channel wiring, not just its return values.
 */

const path = require('path');

const GUARD_PATH = path.resolve(__dirname, '..', 'scripts', 'lib', 'bootstrapIsolationGuard.js');
const {
  assertOverrideNotFromDotenv,
  assertBootstrapDatabaseIsolated,
  OVERRIDE_VAR,
} = require(GUARD_PATH);

describe('bootstrapIsolationGuard — assertOverrideNotFromDotenv()', () => {
  it('refuses when the override key is present in the .env file', () => {
    expect(() => assertOverrideNotFromDotenv({ [OVERRIDE_VAR]: 'true' }))
      .toThrow(/present in \.env — refusing to start/);
  });

  it('refuses on PRESENCE regardless of value — "false" in .env is still refused', () => {
    // dotenv never overrides an already-set process.env value, so a key can sit
    // in .env without taking effect this run. It would still be inherited by
    // every future run, which is the whole hazard, so presence is what matters.
    expect(() => assertOverrideNotFromDotenv({ [OVERRIDE_VAR]: 'false' }))
      .toThrow(/present in \.env/);
    expect(() => assertOverrideNotFromDotenv({ [OVERRIDE_VAR]: '' }))
      .toThrow(/present in \.env/);
  });

  it('marks the refusal as qodiqaIsolationFatal so bootstrap-dev exits instead of warn-and-continuing', () => {
    // provisionDevConsent() failures are best-effort by design; only this flag
    // routes to bootstrap-dev.js's exit(1) path.
    let caught = null;
    try { assertOverrideNotFromDotenv({ [OVERRIDE_VAR]: 'true' }); } catch (e) { caught = e; }
    expect(caught).not.toBeNull();
    expect(caught.qodiqaIsolationFatal).toBe(true);
  });

  it('names the inline-invocation remedy in its message', () => {
    expect(() => assertOverrideNotFromDotenv({ [OVERRIDE_VAR]: 'true' }))
      .toThrow(new RegExp(`${OVERRIDE_VAR}=true npm run dev`));
  });

  it('allows an .env with unrelated keys, and a missing/absent parsed object', () => {
    expect(() => assertOverrideNotFromDotenv({ QODIQA_PG_HOST: 'localhost' })).not.toThrow();
    expect(() => assertOverrideNotFromDotenv({})).not.toThrow();
    expect(() => assertOverrideNotFromDotenv(undefined)).not.toThrow();
    expect(() => assertOverrideNotFromDotenv(null)).not.toThrow();
  });

  it('is not fooled by an inherited prototype property named like the override', () => {
    const proto = { [OVERRIDE_VAR]: 'true' };
    const parsed = Object.create(proto);
    // Not an own property of the parsed .env contents — must not refuse.
    expect(() => assertOverrideNotFromDotenv(parsed)).not.toThrow();
  });
});

describe('bootstrapIsolationGuard — assertBootstrapDatabaseIsolated()', () => {
  const ORIGINAL = { db: process.env.QODIQA_PG_DATABASE, override: process.env[OVERRIDE_VAR] };

  afterEach(() => {
    if (ORIGINAL.db === undefined) delete process.env.QODIQA_PG_DATABASE;
    else process.env.QODIQA_PG_DATABASE = ORIGINAL.db;
    if (ORIGINAL.override === undefined) delete process.env[OVERRIDE_VAR];
    else process.env[OVERRIDE_VAR] = ORIGINAL.override;
  });

  it('allows a run that generated its own disposable database', () => {
    delete process.env[OVERRIDE_VAR];
    process.env.QODIQA_PG_DATABASE = 'qodiqa_dev_deadbeef';
    expect(() => assertBootstrapDatabaseIsolated({ generatedDbName: 'qodiqa_dev_deadbeef' }))
      .not.toThrow();
  });

  it('refuses a run against a database it did not generate', () => {
    delete process.env[OVERRIDE_VAR];
    process.env.QODIQA_PG_DATABASE = 'qodiqa';
    expect(() => assertBootstrapDatabaseIsolated({ generatedDbName: null }))
      .toThrow(/Refusing to bootstrap against the non-isolated database "qodiqa"/);
  });

  it('refuses the mechanism specifically: QODIQA_PG_DATABASE backfilled from .env', () => {
    // The incident shape — the operator intended isolation, PowerShell dropped
    // the empty variable, dotenv supplied `qodiqa`, and generatedDbName stayed
    // null because QODIQA_PG_DATABASE was (now) truthy.
    delete process.env[OVERRIDE_VAR];
    process.env.QODIQA_PG_DATABASE = 'qodiqa';
    let caught = null;
    try { assertBootstrapDatabaseIsolated({ generatedDbName: null }); } catch (e) { caught = e; }
    expect(caught).not.toBeNull();
    expect(caught.qodiqaIsolationFatal).toBe(true);
    expect(caught.message).toMatch(/Unset QODIQA_PG_DATABASE/);
  });

  it('refuses even when QODIQA_PG_DATABASE is unset, naming the shared default', () => {
    delete process.env[OVERRIDE_VAR];
    delete process.env.QODIQA_PG_DATABASE;
    expect(() => assertBootstrapDatabaseIsolated({ generatedDbName: null }))
      .toThrow(/non-isolated database "qodiqa"/);
  });

  it('proceeds with a loud warning when the override is passed inline', () => {
    process.env[OVERRIDE_VAR] = 'true';
    process.env.QODIQA_PG_DATABASE = 'qodiqa';
    const warnings = [];
    expect(() => assertBootstrapDatabaseIsolated({
      generatedDbName: null, warn: (m) => warnings.push(m),
    })).not.toThrow();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/proceeding against the non-isolated database "qodiqa"/);
    // The warning must state the actual consequence, not just that it proceeded.
    expect(warnings[0]).toMatch(/no file-side counterpart/);
  });

  it('treats any override value other than the exact string "true" as absent', () => {
    process.env.QODIQA_PG_DATABASE = 'qodiqa';
    for (const value of ['TRUE', '1', 'yes', '']) {
      process.env[OVERRIDE_VAR] = value;
      expect(() => assertBootstrapDatabaseIsolated({ generatedDbName: null }))
        .toThrow(/Refusing to bootstrap/);
    }
  });
});
