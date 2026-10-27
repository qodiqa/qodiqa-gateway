'use strict';

/**
 * Migration Runner Tests — Migration 031 (CHAIN-2 audit chain verifier state table)
 *
 * MIG-031-01 … MIG-031-03  Runner orchestration: fresh install, upgraded install,
 *                          idempotent repeat
 * MIG-031-04 … MIG-031-07  Migration file content: singleton-row table shape,
 *                          RLS policies mirror audit_chain_head's, grants,
 *                          transaction wrapping + idempotency marker
 *
 * Mirrors the fake-pool pattern in migration027/028/029/030.test.js.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATION_FILE = path.join(__dirname, '../migrations/031_audit_chain_verifier_state.sql');

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

describe('MIG-031-01 … MIG-031-03: migration runner orchestration', () => {
  test('MIG-031-01 fresh installation applies every migration, including 031, in order', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ pool: db });

    const versions = result.applied.map(m => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    expect(versions).toContain(31);
    expect(result.applied.some(m => m.filename === '031_audit_chain_verifier_state.sql')).toBe(true);
    expect(db.applied.has(31)).toBe(true);
  });

  test('MIG-031-02 upgraded installation (1..30 already applied) applies 031 next, in order', async () => {
    const preApplied = [];
    for (let v = 1; v <= 30; v++) {
      preApplied.push({ version: v, name: `migration_${v}`, checksum: 'PLACEHOLDER_CHECKSUM' });
    }
    const db = makeFakeMigrationsDb(preApplied);

    const result = await runMigrations({ pool: db });

    // Not "applies exactly one migration" — later migrations (e.g. 032,
    // the CHAIN-3 persistence recovery queue table) are also pending from
    // this state and are expected to apply too, same convention as
    // migration030.test.js's MIG-030-02. What this test guarantees is that
    // 031 specifically applies, and applies before any migration newer
    // than itself.
    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied[0].version).toBe(31);
    expect(result.applied[0].name).toBe('audit_chain_verifier_state');
    expect(result.applied.every(m => m.version >= 31)).toBe(true);
  });

  test('MIG-031-03 repeated execution is idempotent — a second run finds nothing pending', async () => {
    const db = makeFakeMigrationsDb([]);

    const first = await runMigrations({ pool: db });
    expect(first.applied.length).toBeGreaterThan(0);

    const second = await runMigrations({ pool: db });
    expect(second.applied.length).toBe(0);
    expect(second.skipped).toBe(first.applied.length);
  });
});

describe('MIG-031-04 … MIG-031-07: migration 031 file content', () => {
  const content = fs.readFileSync(MIGRATION_FILE, 'utf8');

  test('MIG-031-04 creates a singleton-row table with the expected watermark columns', () => {
    expect(content).toMatch(/CREATE TABLE IF NOT EXISTS audit_chain_verifier_state/);
    expect(content).toMatch(/id\s+INTEGER\s+PRIMARY KEY DEFAULT 1/);
    expect(content).toMatch(/CONSTRAINT audit_chain_verifier_state_singleton CHECK \(id = 1\)/);
    expect(content).toMatch(/last_verified_seq\s+BIGINT/);
    expect(content).toMatch(/last_verified_hash\s+CHAR\(64\)/);
    expect(content).toMatch(/last_pg_divergence_seq\s+BIGINT/);
  });

  test('MIG-031-05 RLS policies mirror audit_chain_head\'s mutable-pointer-table shape (SELECT/INSERT/UPDATE, not DELETE)', () => {
    expect(content).toMatch(/ALTER TABLE audit_chain_verifier_state ENABLE ROW LEVEL SECURITY;/);
    expect(content).toMatch(/ALTER TABLE audit_chain_verifier_state FORCE ROW LEVEL SECURITY;/);
    expect(content).toMatch(/CREATE POLICY audit_chain_verifier_state_select ON audit_chain_verifier_state FOR SELECT/);
    expect(content).toMatch(/CREATE POLICY audit_chain_verifier_state_insert ON audit_chain_verifier_state FOR INSERT/);
    expect(content).toMatch(/CREATE POLICY audit_chain_verifier_state_update ON audit_chain_verifier_state FOR UPDATE/);
    expect(content).not.toMatch(/FOR DELETE/);
  });

  test('MIG-031-06 grants SELECT/INSERT/UPDATE to qodiqa_app and SELECT to qodiqa_read — no DELETE grant anywhere', () => {
    expect(content).toMatch(/GRANT SELECT, INSERT, UPDATE ON audit_chain_verifier_state TO qodiqa_app;/);
    expect(content).toMatch(/GRANT SELECT\s+ON audit_chain_verifier_state TO qodiqa_read;/);
    expect(content).not.toMatch(/\bDELETE\b.*ON audit_chain_verifier_state/);
  });

  test('MIG-031-07 is wrapped in a single BEGIN/COMMIT transaction and records itself idempotently', () => {
    expect(content).toMatch(/^BEGIN;$/m);
    expect(content).toMatch(/^COMMIT;$/m);
    expect(content).toMatch(/INSERT INTO qodiqa_migrations \(version, name, checksum, applied_by\)/);
    expect(content).toMatch(/VALUES \(31, 'audit_chain_verifier_state'/);
    expect(content).toMatch(/ON CONFLICT \(version\) DO NOTHING;/);
  });
});
