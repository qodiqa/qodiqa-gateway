'use strict';

/**
 * OPS-01 (D1) — migrate.js's loud, actionable error on a role-privilege gap.
 *
 * Simulates the SQLSTATE 42501 (insufficient_privilege) condition a
 * genuinely fresh PostgreSQL cluster produces at migration 018's
 * `ALTER ROLE qodiqa_mig BYPASSRLS` when connected as the default
 * QODIQA_PG_MIG_USER — see docs/operations/database-role-management.md and
 * the OPS-01 evidence.
 * This is a MOCKED pool, not a live PostgreSQL cluster — reproducing the
 * real privilege model live requires a genuinely fresh cluster/role state,
 * a named-checkpoint, cluster-level action per this repo's DB-safety
 * practice, not something to spin up per test run. Honestly labeled as
 * simulated: it proves migrate.js's own error-wrapping logic, not
 * PostgreSQL's actual privilege enforcement (exercised live by CI's
 * postgres:17-alpine containers and migration 018's real SQL). Same
 * mock-pool strategy as pool.runMigrations.test.js — real, unmodified
 * _loadMigrationFiles() reads the actual migrations/ directory.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations');

function migrationContent(filename) {
  return fs.readFileSync(path.join(MIGRATIONS_DIR, filename), 'utf8');
}

function permissionDeniedError(message = 'permission denied to alter role') {
  const err = new Error(message);
  err.code = '42501';
  return err;
}

describe('migrate.js — role-privilege error wrapping (OPS-01 / D1)', () => {
  afterEach(() => {
    delete process.env.QODIQA_PG_MIG_USER;
  });

  test('a 42501 error on migration 018 (ALTER ROLE ... BYPASSRLS) is wrapped into a loud, actionable error', async () => {
    const migration018 = migrationContent('018_rls_tenant_isolation.sql');
    expect(migration018).toMatch(/ALTER ROLE qodiqa_mig BYPASSRLS/);

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration018) throw permissionDeniedError();
        return { rows: [] };
      }),
    };

    await expect(runMigrations({ pool })).rejects.toThrow(/PG_MIGRATE_ROLE_PRIVILEGE_DENIED/);
  });

  test('the wrapped error names the failing migration, the connected-as identity, and the documented remedy', async () => {
    const migration018 = migrationContent('018_rls_tenant_isolation.sql');
    process.env.QODIQA_PG_MIG_USER = 'qodiqa_mig';

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration018) throw permissionDeniedError();
        return { rows: [] };
      }),
    };

    let caught;
    try { await runMigrations({ pool }); } catch (err) { caught = err; }

    expect(caught).toBeDefined();
    expect(caught.qodiqaRolePrivilegeGap).toBe(true);
    expect(caught.message).toContain('018_rls_tenant_isolation.sql');
    expect(caught.message).toContain('qodiqa_mig');
    expect(caught.message).toContain('docs/operations/database-role-management.md');
  });

  test('a 42501 error on a migration with no role-DDL statement is NOT relabeled — detection stays narrow', async () => {
    const migration001 = migrationContent('001_initial_schema.sql');
    // Deliberately checks the SAME narrow pattern migrate.js's own
    // ROLE_DDL_PATTERN uses (CREATE/ALTER/DROP ROLE), not a bare /ROLE/i
    // check — migration 001 legitimately contains the word "role" as a
    // column name (rbac_users.role) and an index name (idx_rbac_users_role),
    // neither of which is a role-management DDL statement.
    expect(migration001).not.toMatch(/\b(ALTER|CREATE|DROP)\s+ROLE\b/i);

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration001) throw permissionDeniedError('permission denied for schema public');
        return { rows: [] };
      }),
    };

    let caught;
    try { await runMigrations({ pool }); } catch (err) { caught = err; }

    expect(caught).toBeDefined();
    expect(caught.message).toBe('permission denied for schema public');
    expect(caught.qodiqaRolePrivilegeGap).toBeUndefined();
  });

  test('a non-42501 error on migration 018 is NOT relabeled — detection requires the exact SQLSTATE', async () => {
    const migration018 = migrationContent('018_rls_tenant_isolation.sql');
    const otherError = new Error('connection terminated unexpectedly');
    otherError.code = '57P01';

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration018) throw otherError;
        return { rows: [] };
      }),
    };

    await expect(runMigrations({ pool })).rejects.toThrow('connection terminated unexpectedly');
  });
});

describe('migrate.js — ownership-check error wrapping', () => {
  afterEach(() => {
    delete process.env.QODIQA_PG_MIG_USER;
  });

  function ownershipError(message = 'must be owner of table audit_chain') {
    // PostgreSQL's real ownership-check failures are also reported under
    // 42501 (insufficient_privilege) -- included here to match the live
    // behavior reproduced, but the wrapper's own detection
    // does not require it (see the third test below).
    const err = new Error(message);
    err.code = '42501';
    return err;
  }

  test('a "must be owner of" error on migration 055 (ALTER TABLE ... OWNER TO) is wrapped into a loud, actionable error', async () => {
    const migration055 = migrationContent('055_mig_table_ownership_transfer.sql');
    expect(migration055).toMatch(/OWNER TO qodiqa_mig/);

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration055) throw ownershipError();
        return { rows: [] };
      }),
    };

    let caught;
    try { await runMigrations({ pool }); } catch (err) { caught = err; }

    expect(caught).toBeDefined();
    expect(caught.qodiqaRolePrivilegeGap).toBe(true);
    expect(caught.message).toContain('055_mig_table_ownership_transfer.sql');
    expect(caught.message).toContain('must be owner of table audit_chain');
    expect(caught.message).toContain('docs/operations/database-role-management.md');
  });

  test('an ownership-check error on migration 021 (CREATE INDEX ... ON audit_chain, no ALTER TABLE/OWNER TO keyword at all) is also wrapped — detection is on the error message, not a content keyword', async () => {
    const migration021 = migrationContent('021_audit_chain_index_optimization.sql');
    expect(migration021).toMatch(/CREATE\s+(UNIQUE\s+)?INDEX/i);
    expect(migration021).not.toMatch(/OWNER\s+TO/i);
    expect(migration021).not.toMatch(/\bALTER\s+TABLE\b/i);

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration021) throw ownershipError('must be owner of relation audit_chain');
        return { rows: [] };
      }),
    };

    let caught;
    try { await runMigrations({ pool }); } catch (err) { caught = err; }

    expect(caught).toBeDefined();
    expect(caught.qodiqaRolePrivilegeGap).toBe(true);
    expect(caught.message).toContain('021_audit_chain_index_optimization.sql');
  });

  test('an ownership-check error is detected by message text alone, regardless of SQLSTATE', async () => {
    const migration055 = migrationContent('055_mig_table_ownership_transfer.sql');
    const err = new Error('must be owner of table audit_chain');
    err.code = undefined; // deliberately no SQLSTATE, unlike the role-DDL branch's own requirement

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration055) throw err;
        return { rows: [] };
      }),
    };

    let caught;
    try { await runMigrations({ pool }); } catch (e) { caught = e; }

    expect(caught).toBeDefined();
    expect(caught.qodiqaRolePrivilegeGap).toBe(true);
  });

  test('an unrelated permission error (message does not say "must be owner of") is NOT relabeled — detection is narrow to the exact PostgreSQL ownership-check wording', async () => {
    const migration001 = migrationContent('001_initial_schema.sql');

    const pool = {
      query: jest.fn(async (sql) => {
        if (sql === migration001) throw ownershipError('permission denied for table qodiqa_migrations');
        return { rows: [] };
      }),
    };

    let caught;
    try { await runMigrations({ pool }); } catch (e) { caught = e; }

    expect(caught).toBeDefined();
    expect(caught.message).toBe('permission denied for table qodiqa_migrations');
    expect(caught.qodiqaRolePrivilegeGap).toBeUndefined();
  });
});
