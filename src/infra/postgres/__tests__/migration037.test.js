'use strict';

/**
 * Migration Runner Tests — Migration 037 (Finding B: audit chain
 * hash-sentinel columns CHAR(64) padding fix)
 *
 * MIG-037-01 … MIG-037-03  Runner orchestration: fresh install, upgraded install,
 *                          idempotent repeat
 * MIG-037-04 … MIG-037-08  Migration file content: both columns retyped to
 *                          VARCHAR(64), CHECK constraints added, transaction
 *                          wrapping + idempotency marker
 *
 * Mirrors the fake-pool pattern in migration027..032.test.js.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATION_FILE = path.join(__dirname, '../migrations/037_audit_chain_hash_columns_varchar_fix.sql');

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

describe('MIG-037-01 … MIG-037-03: migration runner orchestration', () => {
  test('MIG-037-01 fresh installation applies every migration, including 037, in order', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ pool: db });

    const versions = result.applied.map(m => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    expect(versions).toContain(37);
    expect(result.applied.some(m => m.filename === '037_audit_chain_hash_columns_varchar_fix.sql')).toBe(true);
    expect(db.applied.has(37)).toBe(true);
  });

  test('MIG-037-02 upgraded installation (1..36 already applied) applies 037 next, in order', async () => {
    const preApplied = [];
    for (let v = 1; v <= 36; v++) {
      preApplied.push({ version: v, name: `migration_${v}`, checksum: 'PLACEHOLDER_CHECKSUM' });
    }
    const db = makeFakeMigrationsDb(preApplied);

    const result = await runMigrations({ pool: db });

    // added migration 038 after this test was written — an upgraded
    // installation with only 1..36 already applied now has TWO pending
    // migrations (037, then 038), not just one. This test's scope is
    // specifically "037 applies next, in the right position" — it asserts
    // that without hard-coding "and nothing else is ever pending after it,"
    // which would make this test re-break on every future migration.
    expect(result.applied.length).toBeGreaterThanOrEqual(1);
    expect(result.applied[0].version).toBe(37);
    expect(result.applied[0].name).toBe('audit_chain_hash_columns_varchar_fix');
  });

  test('MIG-037-03 repeated execution is idempotent — a second run finds nothing pending', async () => {
    const db = makeFakeMigrationsDb([]);

    const first = await runMigrations({ pool: db });
    expect(first.applied.length).toBeGreaterThan(0);

    const second = await runMigrations({ pool: db });
    expect(second.applied.length).toBe(0);
    expect(second.skipped).toBe(first.applied.length);
  });
});

describe('MIG-037-04 … MIG-037-08: migration 037 file content', () => {
  const content = fs.readFileSync(MIGRATION_FILE, 'utf8');

  test('MIG-037-04 retypes audit_chain_head.tail_hash from CHAR(64) to VARCHAR(64), stripping any existing padding', () => {
    expect(content).toMatch(
      /ALTER TABLE audit_chain_head\s+ALTER COLUMN tail_hash TYPE VARCHAR\(64\) USING TRIM\(TRAILING ' ' FROM tail_hash\);/
    );
  });

  test('MIG-037-05 adds a GENESIS-or-64-char CHECK constraint on audit_chain_head.tail_hash, matching audit_chain.prev_hash\'s existing pattern (migration 001)', () => {
    expect(content).toMatch(/DROP CONSTRAINT IF EXISTS audit_chain_head_tail_hash_genesis;/);
    expect(content).toMatch(
      /ADD CONSTRAINT audit_chain_head_tail_hash_genesis\s+CHECK \(tail_hash = 'GENESIS' OR LENGTH\(tail_hash\) = 64\);/
    );
  });

  test('MIG-037-06 retypes audit_chain_verifier_state.last_verified_hash from CHAR(64) to VARCHAR(64), stripping any existing padding', () => {
    expect(content).toMatch(
      /ALTER TABLE audit_chain_verifier_state\s+ALTER COLUMN last_verified_hash TYPE VARCHAR\(64\) USING TRIM\(TRAILING ' ' FROM last_verified_hash\);/
    );
  });

  test('MIG-037-07 adds a NULL-or-GENESIS-or-64-char CHECK constraint on audit_chain_verifier_state.last_verified_hash', () => {
    expect(content).toMatch(/DROP CONSTRAINT IF EXISTS audit_chain_verifier_state_last_verified_hash_genesis;/);
    expect(content).toMatch(
      /ADD CONSTRAINT audit_chain_verifier_state_last_verified_hash_genesis\s+CHECK \(last_verified_hash IS NULL OR last_verified_hash = 'GENESIS' OR LENGTH\(last_verified_hash\) = 64\);/
    );
  });

  test('MIG-037-08 is wrapped in a single BEGIN/COMMIT transaction and records itself idempotently', () => {
    expect(content).toMatch(/^BEGIN;$/m);
    expect(content).toMatch(/^COMMIT;$/m);
    expect(content).toMatch(/INSERT INTO qodiqa_migrations \(version, name, checksum, applied_by\)/);
    expect(content).toMatch(/VALUES \(37, 'audit_chain_hash_columns_varchar_fix'/);
    expect(content).toMatch(/ON CONFLICT \(version\) DO NOTHING;/);
  });
});
