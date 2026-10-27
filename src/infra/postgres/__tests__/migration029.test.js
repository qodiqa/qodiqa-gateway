'use strict';

/**
 * Migration Runner Tests — (policy governance / maker-checker framework)
 *
 * MIG-029-01 … MIG-029-04  Runner orchestration: fresh install, upgraded install,
 *                          idempotent repeat, dry-run
 * MIG-029-05 … MIG-029-13  Migration file content: tables, grants, RLS policies,
 *                          idempotency markers, transaction wrapping,
 *                          append-only invariants, optimistic-locking trigger,
 *                          no weakening of pre-existing grants
 *
 * Mirrors the fake-pool pattern in migration027/028.test.js: the runner
 * loads the REAL migrations directory from disk via an in-memory fake
 * `pool`, so this exercises the actual file list — including 029 — without
 * a real database.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATION_FILE = path.join(__dirname, '../migrations/029_policy_governance.sql');

function makeFakeMigrationsDb(initialApplied = []) {
  const applied = new Map(initialApplied.map(m => [m.version, m]));
  return {
    applied,
    query: jest.fn(async (sql, params) => {
      const s = sql.trim();
      if (s.startsWith('CREATE TABLE IF NOT EXISTS qodiqa_migrations')) {
        return {};
      }
      if (s.startsWith('SELECT version, name, checksum FROM qodiqa_migrations')) {
        return { rows: [...applied.values()] };
      }
      if (s.startsWith('INSERT INTO qodiqa_migrations (version, name, checksum)')) {
        const [version, name, checksum] = params;
        applied.set(version, { version, name, checksum });
        return {};
      }
      return {};
    }),
  };
}

describe('MIG-029-01 … MIG-029-04: migration runner orchestration', () => {
  test('MIG-029-01 fresh installation applies every migration, including 029, in order', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ pool: db });

    const versions = result.applied.map(m => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    expect(versions).toContain(29);
    expect(result.applied.some(m => m.filename === '029_policy_governance.sql')).toBe(true);
    expect(db.applied.has(29)).toBe(true);
  });

  test('MIG-029-02 upgraded installation (1..28 already applied) applies 029 next, in order', async () => {
    const preApplied = [];
    for (let v = 1; v <= 28; v++) {
      preApplied.push({ version: v, name: `migration_${v}`, checksum: 'PLACEHOLDER_CHECKSUM' });
    }
    const db = makeFakeMigrationsDb(preApplied);

    const result = await runMigrations({ pool: db });

    // Not "applies exactly one migration" — later migrations (e.g. 030,
    // the webhook KEK doc fix) are also pending from this state and
    // are expected to apply too. What this test guarantees is that 029
    // specifically applies, and applies before any migration newer than itself.
    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied[0].version).toBe(29);
    expect(result.applied[0].name).toBe('policy_governance');
    expect(result.applied.every(m => m.version >= 29)).toBe(true);
  });

  test('MIG-029-03 repeated execution is idempotent — a second run finds nothing pending', async () => {
    const db = makeFakeMigrationsDb([]);

    const first = await runMigrations({ pool: db });
    expect(first.applied.length).toBeGreaterThan(0);

    const second = await runMigrations({ pool: db });
    expect(second.applied.length).toBe(0);
    expect(second.skipped).toBe(first.applied.length);
  });

  test('MIG-029-04 dry-run does not mutate the migrations table', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ dryRun: true, pool: db });

    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied.every(m => m.dryRun)).toBe(true);
    expect(db.applied.size).toBe(0);
  });
});

describe('MIG-029-05 … MIG-029-13: migration 029 file content', () => {
  const content = fs.readFileSync(MIGRATION_FILE, 'utf8');

  test('MIG-029-05 creates all six governance tables', () => {
    for (const table of [
      'policy_change_requests', 'policy_reviews', 'policy_approvals',
      'policy_rollbacks', 'policy_publications', 'policy_emergency_activations', 'approval_events',
    ]) {
      expect(content).toMatch(new RegExp(`CREATE TABLE IF NOT EXISTS ${table} `));
    }
  });

  test('MIG-029-06 policy_change_requests and policy_emergency_activations are mutable (grant UPDATE); the four evidence tables are not', () => {
    expect(content).toMatch(/GRANT SELECT, INSERT, UPDATE ON policy_change_requests\s+TO qodiqa_app;/);
    expect(content).toMatch(/GRANT SELECT, INSERT, UPDATE ON policy_emergency_activations TO qodiqa_app;/);
    for (const table of ['policy_reviews', 'policy_approvals', 'policy_rollbacks', 'policy_publications', 'approval_events']) {
      expect(content).toMatch(new RegExp(`GRANT SELECT, INSERT ON ${table}\\s+TO qodiqa_app;`));
      expect(content).not.toMatch(new RegExp(`GRANT[^;]*UPDATE[^;]*ON ${table}\\b`));
    }
  });

  test('MIG-029-07 never grants DELETE on any table in this migration', () => {
    expect(content).not.toMatch(/GRANT[^;]*DELETE/);
  });

  test('MIG-029-08 never touches consent_records / consent_audit_log / audit_chain / platform_audit_events / policy_provenance_versions grants', () => {
    // must not weaken the pre-existing immutability invariants
    // those tables already have, nor conflate the new mutable workflow
    // gate with the pre-existing read-only forensic provenance ledger.
    for (const table of ['consent_records', 'consent_audit_log', 'audit_chain', 'platform_audit_events', 'policy_provenance_versions']) {
      expect(content).not.toMatch(new RegExp(`GRANT[^;]*ON ${table}\\b`));
    }
  });

  test('MIG-029-09 enables and forces row-level security on every new table, tenant-aware like consent_records', () => {
    for (const table of [
      'policy_change_requests', 'policy_reviews', 'policy_approvals',
      'policy_rollbacks', 'policy_publications', 'policy_emergency_activations', 'approval_events',
    ]) {
      expect(content).toMatch(new RegExp(`ALTER TABLE ${table}\\s+ENABLE ROW LEVEL SECURITY;`));
      expect(content).toMatch(new RegExp(`ALTER TABLE ${table}\\s+FORCE ROW LEVEL SECURITY;`));
    }
    expect(content).toMatch(/tenant_id IS NULL OR tenant_id = qodiqa_current_tenant\(\)/);
  });

  test('MIG-029-10 policy_change_requests has an optimistic-locking version column with a trigger, mirroring consent_records', () => {
    expect(content).toMatch(/version\s+INTEGER\s+NOT NULL DEFAULT 1/);
    expect(content).toMatch(/NEW\.version\s*=\s*OLD\.version \+ 1;/);
    expect(content).toMatch(/CREATE TRIGGER policy_change_requests_updated_at/);
  });

  test('MIG-029-11 is idempotent: drops policies before creating them and uses ON CONFLICT DO NOTHING', () => {
    expect(content).toMatch(/DROP POLICY IF EXISTS pcr_tenant_select ON policy_change_requests;/);
    expect(content).toMatch(/DROP POLICY IF EXISTS ae_tenant_select ON approval_events;/);
    expect(content).toMatch(/ON CONFLICT \(version\) DO NOTHING;/);
  });

  test('MIG-029-12 is wrapped in a single BEGIN/COMMIT transaction', () => {
    expect(content).toMatch(/^BEGIN;$/m);
    expect(content).toMatch(/^COMMIT;$/m);
  });

  test('MIG-029-13 request_type and status are constrained to the documented enums', () => {
    expect(content).toMatch(/request_type IN \('CREATE', 'UPDATE', 'ENABLE', 'DISABLE', 'ROLLBACK', 'ARCHIVE'\)/);
    expect(content).toMatch(/status IN \('DRAFT', 'SUBMITTED', 'IN_REVIEW', 'REVIEWED', 'APPROVED',/);
  });
});
