'use strict';

/**
 * Migration Runner Tests — (platform_audit_events retention grants fix)
 *
 * MIG-027-01 … MIG-027-04  Runner orchestration: fresh install, upgraded install,
 *                          idempotent repeat, dry-run
 * MIG-027-05 … MIG-027-09  Migration file content: grants, least privilege,
 *                          policies, idempotency markers, transaction wrapping
 *
 * The runner tests load the REAL migrations directory from disk (migrate.js's
 * MIGRATIONS_DIR is not overridable) via a fully in-memory fake `pool`, so they
 * exercise the actual file list — including 027 — without a real database.
 * This mirrors the fake-pool pattern used throughout src/infra/postgres/__tests__.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATION_FILE = path.join(__dirname, '../migrations/027_platform_audit_events_retention_grants_fix.sql');

// In-memory qodiqa_migrations table. Distinguishes the runner's own
// bookkeeping INSERT (parameterized, exact literal SQL) from a migration
// file's raw content execution (a single unparameterized multi-statement
// string) so each is handled correctly — see migrate.js:135-142.
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
      // Raw migration file content (BEGIN ... COMMIT) — simulate success.
      return {};
    }),
  };
}

describe('MIG-027-01 … MIG-027-04: migration runner orchestration', () => {
  test('MIG-027-01 fresh installation applies every migration, including 027, in order', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ pool: db });

    expect(result.applied.length).toBeGreaterThan(0);
    const versions = result.applied.map(m => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    // Not "the last version is 27" — later migrations are
    // expected to be added over time. What this test guarantees is that a
    // fresh install still applies 027 itself, in its correct sorted position.
    expect(versions).toContain(27);
    expect(result.applied.some(m => m.filename === '027_platform_audit_events_retention_grants_fix.sql')).toBe(true);
    expect(db.applied.has(27)).toBe(true);
  });

  test('MIG-027-02 upgraded installation (1..26 already applied) applies 027 next, in order', async () => {
    const preApplied = [];
    for (let v = 1; v <= 26; v++) {
      preApplied.push({ version: v, name: `migration_${v}`, checksum: 'PLACEHOLDER_CHECKSUM' });
    }
    const db = makeFakeMigrationsDb(preApplied);

    const result = await runMigrations({ pool: db });

    // Not "applies exactly one migration" — later migrations (e.g. 028,
    //) are also pending from this state and are expected to apply
    // too. What this test guarantees is that 027 specifically applies, and
    // applies before any migration newer than itself.
    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied[0].version).toBe(27);
    expect(result.applied[0].name).toBe('platform_audit_events_retention_grants_fix');
    expect(result.applied.every(m => m.version >= 27)).toBe(true);
  });

  test('MIG-027-03 repeated execution is idempotent — a second run finds nothing pending', async () => {
    const db = makeFakeMigrationsDb([]);

    const first = await runMigrations({ pool: db });
    expect(first.applied.length).toBeGreaterThan(0);

    const second = await runMigrations({ pool: db });
    expect(second.applied.length).toBe(0);
    expect(second.skipped).toBe(first.applied.length);
  });

  test('MIG-027-04 dry-run does not mutate the migrations table', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ dryRun: true, pool: db });

    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied.every(m => m.dryRun)).toBe(true);
    expect(db.applied.size).toBe(0);
  });
});

describe('MIG-027-05 … MIG-027-09: migration 027 file content', () => {
  const content = fs.readFileSync(MIGRATION_FILE, 'utf8');

  test('MIG-027-05 grants UPDATE and DELETE to qodiqa_app on platform_audit_events', () => {
    expect(content).toMatch(/GRANT UPDATE, DELETE ON platform_audit_events TO qodiqa_app;/);
  });

  test('MIG-027-06 does not grant UPDATE/DELETE to any role other than qodiqa_app (least privilege)', () => {
    const grantLines = content.split('\n').filter(l => /^GRANT\s/.test(l.trim()));
    expect(grantLines.length).toBeGreaterThan(0);
    for (const line of grantLines) {
      expect(line).toMatch(/TO qodiqa_app;?\s*$/);
    }
  });

  test('MIG-027-07 creates UPDATE and DELETE policies scoped to qodiqa_app only', () => {
    expect(content).toMatch(/CREATE POLICY pae_system_update[\s\S]*?FOR UPDATE TO qodiqa_app/);
    expect(content).toMatch(/CREATE POLICY pae_system_delete[\s\S]*?FOR DELETE TO qodiqa_app/);
  });

  test('MIG-027-08 is idempotent: drops policies before creating them and uses ON CONFLICT DO NOTHING', () => {
    expect(content).toMatch(/DROP POLICY IF EXISTS pae_system_update ON platform_audit_events;/);
    expect(content).toMatch(/DROP POLICY IF EXISTS pae_system_delete ON platform_audit_events;/);
    expect(content).toMatch(/ON CONFLICT \(version\) DO NOTHING;/);
  });

  test('MIG-027-09 is wrapped in a single BEGIN/COMMIT transaction', () => {
    expect(content).toMatch(/^BEGIN;$/m);
    expect(content).toMatch(/^COMMIT;$/m);
  });
});
