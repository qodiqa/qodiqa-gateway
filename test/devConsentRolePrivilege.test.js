'use strict';

/**
 * OPS-01 (D2) — devConsent.js fails loudly instead of silently leaving an
 * explicit-QODIQA_PG_DATABASE database created-but-unmigrated.
 *
 * Mirrors FINDINGS-GROUP-B-REMEDIATION-REPORT.md §B4's "Control A" real-boot
 * evidence (explicit dummy QODIQA_PG_DATABASE gets created, then hits the
 * unmigrated-schema wall via the default pool) — asserts the FATAL/
 * qodiqaIsolationFatal outcome the code now produces for that case, in
 * place of the prior silent warn-and-continue. Mocked pg.Pool and mocked
 * migrate.js — no real database required; the live mechanism (PG15+
 * schema-privilege denial on a freshly created database) is exercised for
 * real by Control A's original boot evidence, not re-derived here.
 *
 * Lives under test/ (not scripts/lib/__tests__/) so it is actually
 * collected by the test:component gate (testPathPatterns anchors on
 * "^test/") — see OPS-01 closure notes for the CLN-03-pattern gate-
 * collection check this relocation was made to satisfy.
 */

function mockMaintenancePool({ dbExists }) {
  const query = jest.fn(async (sql) => {
    if (sql.startsWith('SELECT 1 FROM pg_database')) {
      return { rows: dbExists ? [{ exists: 1 }] : [] };
    }
    return { rows: [] };
  });
  return { query, end: jest.fn().mockResolvedValue() };
}

describe('devConsent.js — explicit QODIQA_PG_DATABASE, fail-loudly on migration failure after creation (OPS-01 / D2)', () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_DATABASE = 'qodiqa_explicit_test_db';
    process.env.QODIQA_PG_TEST_USER = 'qodiqa_test';
    process.env.QODIQA_PG_TEST_PASSWORD = 'irrelevant';
    // this suite deliberately drives the EXPLICIT-QODIQA_PG_DATABASE
    // path, which is exactly what's isolation guard now refuses by default
    // (bootstrap may only provision a database it generated itself). The
    // override is what an operator would pass inline for a deliberate
    // shared/explicit-database run, so setting it here keeps this suite
    // testing the OPS-01/D2 behavior it was written for rather than colliding
    // with a guard aimed at accidental runs. No real database is touched —
    // pg.Pool and migrate.js are both mocked (see header).
    process.env.QODIQA_PG_ALLOW_SHARED = 'true';
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
  });

  test('DB did not exist, gets created, migration fails -> qodiqaIsolationFatal, not a silent warning', async () => {
    jest.doMock('pg', () => ({ Pool: jest.fn().mockImplementation(() => mockMaintenancePool({ dbExists: false })) }));
    jest.doMock('../src/infra/postgres/migrate', () => ({
      runMigrations: jest.fn().mockRejectedValue(new Error('permission denied for schema public')),
    }));

    const { provisionDevConsent } = require('../scripts/lib/devConsent');

    let caught;
    try { await provisionDevConsent({ clientId: 'dev-local' }); } catch (err) { caught = err; }

    expect(caught).toBeDefined();
    expect(caught.qodiqaIsolationFatal).toBe(true);
    expect(caught.message).toContain('qodiqa_explicit_test_db');
    expect(caught.message).toContain('did not exist and was just created');
  });

  test('DB already existed -> a migration failure is NOT tagged fatal (pre-existing behavior, untouched)', async () => {
    jest.doMock('pg', () => ({ Pool: jest.fn().mockImplementation(() => mockMaintenancePool({ dbExists: true })) }));
    jest.doMock('../src/infra/postgres/migrate', () => ({
      runMigrations: jest.fn().mockRejectedValue(new Error('some unrelated migration error')),
    }));

    const { provisionDevConsent } = require('../scripts/lib/devConsent');

    let caught;
    try { await provisionDevConsent({ clientId: 'dev-local' }); } catch (err) { caught = err; }

    expect(caught).toBeDefined();
    expect(caught.qodiqaIsolationFatal).toBeUndefined();
  });
});
