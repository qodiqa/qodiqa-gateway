'use strict';

/**
 * Migration Runner Tests — Migration 032 (CHAIN-3 durable persistence recovery queue)
 *
 * MIG-032-01 … MIG-032-03  Runner orchestration: fresh install, upgraded install,
 *                          idempotent repeat
 * MIG-032-04 … MIG-032-10  Migration file content: table shape, indexes, RLS
 *                          policies, grants, transaction wrapping + idempotency
 *
 * Mirrors the fake-pool pattern in migration027..031.test.js.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATION_FILE = path.join(__dirname, '../migrations/032_persistence_recovery_queue.sql');

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

describe('MIG-032-01 … MIG-032-03: migration runner orchestration', () => {
  test('MIG-032-01 fresh installation applies every migration, including 032, in order', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ pool: db });

    const versions = result.applied.map(m => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    expect(versions).toContain(32);
    expect(result.applied.some(m => m.filename === '032_persistence_recovery_queue.sql')).toBe(true);
    expect(db.applied.has(32)).toBe(true);
  });

  test('MIG-032-02 upgraded installation (1..31 already applied) applies only 032', async () => {
    const preApplied = [];
    for (let v = 1; v <= 31; v++) {
      preApplied.push({ version: v, name: `migration_${v}`, checksum: 'PLACEHOLDER_CHECKSUM' });
    }
    const db = makeFakeMigrationsDb(preApplied);

    const result = await runMigrations({ pool: db });

    // Not "applies exactly one migration" — later migrations are also
    // pending from this state and are expected to apply too, same
    // convention as migration030.test.js's MIG-030-02 and
    // migration031.test.js's MIG-031-02. What this test guarantees is that
    // 032 specifically applies, and applies before any migration newer
    // than itself.
    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied[0].version).toBe(32);
    expect(result.applied[0].name).toBe('persistence_recovery_queue');
    expect(result.applied.every(m => m.version >= 32)).toBe(true);
  });

  test('MIG-032-03 repeated execution is idempotent — a second run finds nothing pending', async () => {
    const db = makeFakeMigrationsDb([]);

    const first = await runMigrations({ pool: db });
    expect(first.applied.length).toBeGreaterThan(0);

    const second = await runMigrations({ pool: db });
    expect(second.applied.length).toBe(0);
    expect(second.skipped).toBe(first.applied.length);
  });
});

describe('MIG-032-04 … MIG-032-10: migration 032 file content', () => {
  const content = fs.readFileSync(MIGRATION_FILE, 'utf8');

  test('MIG-032-04 creates the table with the expected columns and status constraint', () => {
    expect(content).toMatch(/CREATE TABLE IF NOT EXISTS persistence_recovery_queue/);
    expect(content).toMatch(/operation_id\s+TEXT\s+PRIMARY KEY/);
    expect(content).toMatch(/operation_type\s+TEXT\s+NOT NULL/);
    expect(content).toMatch(/payload\s+JSONB\s+NOT NULL/);
    expect(content).toMatch(/CHECK \(status IN \('PENDING', 'DLQ', 'ARCHIVED'\)\)/);
    expect(content).toMatch(/eligible_at\s+TIMESTAMPTZ\s+NOT NULL DEFAULT NOW\(\)/);
    expect(content).toMatch(/error_history\s+JSONB\s+NOT NULL DEFAULT '\[\]'::jsonb/);
  });

  test('MIG-032-05 defines partial indexes supporting the claim query and DLQ/archived listings', () => {
    expect(content).toMatch(/CREATE INDEX IF NOT EXISTS idx_prq_claim/);
    expect(content).toMatch(/idx_prq_claim[\s\S]*?WHERE status = 'PENDING'/);
    expect(content).toMatch(/CREATE INDEX IF NOT EXISTS idx_prq_dlq\b/);
    expect(content).toMatch(/CREATE INDEX IF NOT EXISTS idx_prq_archived/);
    expect(content).toMatch(/CREATE INDEX IF NOT EXISTS idx_prq_dlq_type_service/);
  });

  test('MIG-032-06 enables and forces row level security', () => {
    expect(content).toMatch(/ALTER TABLE persistence_recovery_queue ENABLE ROW LEVEL SECURITY;/);
    expect(content).toMatch(/ALTER TABLE persistence_recovery_queue FORCE ROW LEVEL SECURITY;/);
  });

  test('MIG-032-07 defines permissive platform-level policies for SELECT/INSERT/UPDATE/DELETE', () => {
    expect(content).toMatch(/CREATE POLICY prq_select ON persistence_recovery_queue\s+FOR SELECT TO qodiqa_app, qodiqa_read USING \(true\);/);
    expect(content).toMatch(/CREATE POLICY prq_insert ON persistence_recovery_queue\s+FOR INSERT TO qodiqa_app WITH CHECK \(true\);/);
    expect(content).toMatch(/CREATE POLICY prq_update ON persistence_recovery_queue\s+FOR UPDATE TO qodiqa_app USING \(true\) WITH CHECK \(true\);/);
    expect(content).toMatch(/CREATE POLICY prq_delete ON persistence_recovery_queue\s+FOR DELETE TO qodiqa_app USING \(true\);/);
  });

  test('MIG-032-08 grants SELECT/INSERT/UPDATE/DELETE to qodiqa_app and SELECT to qodiqa_read', () => {
    expect(content).toMatch(/GRANT SELECT, INSERT, UPDATE, DELETE ON persistence_recovery_queue TO qodiqa_app;/);
    expect(content).toMatch(/GRANT SELECT\s+ON persistence_recovery_queue TO qodiqa_read;/);
  });

  test('MIG-032-09 uses DROP POLICY IF EXISTS for idempotent re-application', () => {
    const dropCount = (content.match(/DROP POLICY IF EXISTS/g) || []).length;
    expect(dropCount).toBeGreaterThanOrEqual(4);
  });

  test('MIG-032-10 is wrapped in a single BEGIN/COMMIT transaction and records itself idempotently', () => {
    expect(content).toMatch(/^BEGIN;$/m);
    expect(content).toMatch(/^COMMIT;$/m);
    expect(content).toMatch(/INSERT INTO qodiqa_migrations \(version, name, checksum, applied_by\)/);
    expect(content).toMatch(/VALUES \(32, 'persistence_recovery_queue'/);
    expect(content).toMatch(/ON CONFLICT \(version\) DO NOTHING;/);
  });
});
