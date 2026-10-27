'use strict';

/**
 * Migration Runner Tests — (GDPR Data Subject Rights framework)
 *
 * MIG-028-01 … MIG-028-04  Runner orchestration: fresh install, upgraded install,
 *                          idempotent repeat, dry-run
 * MIG-028-05 … MIG-028-12  Migration file content: tables, grants, RLS policies,
 *                          idempotency markers, transaction wrapping,
 *                          append-only invariant on the three evidence tables
 *
 * Mirrors the fake-pool pattern in migration027.test.js: the runner loads the
 * REAL migrations directory from disk via an in-memory fake `pool`, so this
 * exercises the actual file list — including 028 — without a real database.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATION_FILE = path.join(__dirname, '../migrations/028_dsr_framework.sql');

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

describe('MIG-028-01 … MIG-028-04: migration runner orchestration', () => {
  test('MIG-028-01 fresh installation applies every migration, including 028, in order', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ pool: db });

    const versions = result.applied.map(m => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    // Not "the last version is 28" — later migrations
    // are expected to be added over time. What this test guarantees is
    // that a fresh install still applies 028 itself, in its correct
    // sorted position.
    expect(versions).toContain(28);
    expect(result.applied.some(m => m.filename === '028_dsr_framework.sql')).toBe(true);
    expect(db.applied.has(28)).toBe(true);
  });

  test('MIG-028-02 upgraded installation (1..27 already applied) applies 028 next, in order', async () => {
    const preApplied = [];
    for (let v = 1; v <= 27; v++) {
      preApplied.push({ version: v, name: `migration_${v}`, checksum: 'PLACEHOLDER_CHECKSUM' });
    }
    const db = makeFakeMigrationsDb(preApplied);

    const result = await runMigrations({ pool: db });

    // Not "applies exactly one migration" — later migrations (e.g. 029,
    //) are also pending from this state and are expected to apply
    // too. What this test guarantees is that 028 specifically applies, and
    // applies before any migration newer than itself.
    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied[0].version).toBe(28);
    expect(result.applied[0].name).toBe('dsr_framework');
    expect(result.applied.every(m => m.version >= 28)).toBe(true);
  });

  test('MIG-028-03 repeated execution is idempotent — a second run finds nothing pending', async () => {
    const db = makeFakeMigrationsDb([]);

    const first = await runMigrations({ pool: db });
    expect(first.applied.length).toBeGreaterThan(0);

    const second = await runMigrations({ pool: db });
    expect(second.applied.length).toBe(0);
    expect(second.skipped).toBe(first.applied.length);
  });

  test('MIG-028-04 dry-run does not mutate the migrations table', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ dryRun: true, pool: db });

    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied.every(m => m.dryRun)).toBe(true);
    expect(db.applied.size).toBe(0);
  });
});

describe('MIG-028-05 … MIG-028-12: migration 028 file content', () => {
  const content = fs.readFileSync(MIGRATION_FILE, 'utf8');

  test('MIG-028-05 creates all four DSR tables', () => {
    expect(content).toMatch(/CREATE TABLE IF NOT EXISTS dsr_requests/);
    expect(content).toMatch(/CREATE TABLE IF NOT EXISTS dsr_request_events/);
    expect(content).toMatch(/CREATE TABLE IF NOT EXISTS dsr_rectifications/);
    expect(content).toMatch(/CREATE TABLE IF NOT EXISTS dsr_exports/);
  });

  test('MIG-028-06 dsr_requests is mutable (SELECT/INSERT/UPDATE) but never grants DELETE to any table', () => {
    expect(content).toMatch(/GRANT SELECT, INSERT, UPDATE ON dsr_requests\s+TO qodiqa_app;/);
    expect(content).not.toMatch(/GRANT[^;]*DELETE[^;]*ON dsr_/);
  });

  test('MIG-028-07 the three evidence tables (events/rectifications/exports) are append-only: SELECT+INSERT only', () => {
    expect(content).toMatch(/GRANT SELECT, INSERT ON dsr_request_events\s+TO qodiqa_app;/);
    expect(content).toMatch(/GRANT SELECT, INSERT ON dsr_rectifications\s+TO qodiqa_app;/);
    expect(content).toMatch(/GRANT SELECT, INSERT ON dsr_exports\s+TO qodiqa_app;/);
    expect(content).not.toMatch(/GRANT[^;]*UPDATE[^;]*ON dsr_request_events/);
    expect(content).not.toMatch(/GRANT[^;]*UPDATE[^;]*ON dsr_rectifications/);
    expect(content).not.toMatch(/GRANT[^;]*UPDATE[^;]*ON dsr_exports/);
  });

  test('MIG-028-08 never touches consent_records / consent_audit_log / audit_chain / platform_audit_events grants', () => {
    // must not weaken the pre-existing immutability invariants those
    // tables already have (see migrations 007/018/022/027) — this migration
    // is additive-only.
    expect(content).not.toMatch(/GRANT[^;]*ON consent_records/);
    expect(content).not.toMatch(/GRANT[^;]*ON consent_audit_log/);
    expect(content).not.toMatch(/GRANT[^;]*ON audit_chain/);
    expect(content).not.toMatch(/GRANT[^;]*ON platform_audit_events/);
  });

  test('MIG-028-09 enables and forces row-level security on every new table, tenant-aware like consent_records', () => {
    for (const table of ['dsr_requests', 'dsr_request_events', 'dsr_rectifications', 'dsr_exports']) {
      expect(content).toMatch(new RegExp(`ALTER TABLE ${table}\\s+ENABLE ROW LEVEL SECURITY;`));
      expect(content).toMatch(new RegExp(`ALTER TABLE ${table}\\s+FORCE ROW LEVEL SECURITY;`));
    }
    expect(content).toMatch(/tenant_id IS NULL OR tenant_id = qodiqa_current_tenant\(\)/);
  });

  test('MIG-028-10 is idempotent: drops policies before creating them and uses ON CONFLICT DO NOTHING', () => {
    expect(content).toMatch(/DROP POLICY IF EXISTS dsr_req_tenant_select ON dsr_requests;/);
    expect(content).toMatch(/DROP POLICY IF EXISTS dsr_evt_tenant_select ON dsr_request_events;/);
    expect(content).toMatch(/ON CONFLICT \(version\) DO NOTHING;/);
  });

  test('MIG-028-11 is wrapped in a single BEGIN/COMMIT transaction', () => {
    expect(content).toMatch(/^BEGIN;$/m);
    expect(content).toMatch(/^COMMIT;$/m);
  });

  test('MIG-028-12 request_type and status are constrained to the documented enums', () => {
    expect(content).toMatch(/request_type IN \('RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY'\)/);
    expect(content).toMatch(/status IN \('RECEIVED', 'IDENTITY_VERIFIED', 'APPROVED', 'IN_PROGRESS',/);
  });
});
