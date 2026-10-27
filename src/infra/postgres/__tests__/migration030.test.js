'use strict';

/**
 * Migration Runner Tests — Migration 030
 *
 * MIG-030-01 … MIG-030-03  Runner orchestration: fresh install, upgraded install,
 *                          idempotent repeat
 * MIG-030-04 … MIG-030-07  Migration file content: comment-only (no DDL/DML beyond
 *                          COMMENT ON), correct table/columns targeted, transaction
 *                          wrapping, idempotency marker
 *
 * Mirrors the fake-pool pattern in migration027/028/029.test.js.
 */

const fs   = require('fs');
const path = require('path');
const { runMigrations } = require('../migrate');

const MIGRATION_FILE = path.join(__dirname, '../migrations/030_webhook_kek_abstraction_doc_fix.sql');

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

describe('MIG-030-01 … MIG-030-03: migration runner orchestration', () => {
  test('MIG-030-01 fresh installation applies every migration, including 030, in order', async () => {
    const db = makeFakeMigrationsDb([]);

    const result = await runMigrations({ pool: db });

    const versions = result.applied.map(m => m.version);
    expect(versions).toEqual([...versions].sort((a, b) => a - b));
    expect(versions).toContain(30);
    expect(result.applied.some(m => m.filename === '030_webhook_kek_abstraction_doc_fix.sql')).toBe(true);
    expect(db.applied.has(30)).toBe(true);
  });

  test('MIG-030-02 upgraded installation (1..29 already applied) applies 030 next, in order', async () => {
    const preApplied = [];
    for (let v = 1; v <= 29; v++) {
      preApplied.push({ version: v, name: `migration_${v}`, checksum: 'PLACEHOLDER_CHECKSUM' });
    }
    const db = makeFakeMigrationsDb(preApplied);

    const result = await runMigrations({ pool: db });

    // Not "applies exactly one migration" — later migrations (e.g. 031,
    // the CHAIN-2 audit chain verifier state table) are also pending from
    // this state and are expected to apply too, same convention as
    // migration029.test.js's MIG-029-02. What this test guarantees is that
    // 030 specifically applies, and applies before any migration newer
    // than itself.
    expect(result.applied.length).toBeGreaterThan(0);
    expect(result.applied[0].version).toBe(30);
    expect(result.applied[0].name).toBe('webhook_kek_abstraction_doc_fix');
    expect(result.applied.every(m => m.version >= 30)).toBe(true);
  });

  test('MIG-030-03 repeated execution is idempotent — a second run finds nothing pending', async () => {
    const db = makeFakeMigrationsDb([]);

    const first = await runMigrations({ pool: db });
    expect(first.applied.length).toBeGreaterThan(0);

    const second = await runMigrations({ pool: db });
    expect(second.applied.length).toBe(0);
    expect(second.skipped).toBe(first.applied.length);
  });
});

describe('MIG-030-04 … MIG-030-07: migration 030 file content', () => {
  const content = fs.readFileSync(MIGRATION_FILE, 'utf8');

  test('MIG-030-04 contains only COMMENT ON statements — no table, column, grant, or policy changes', () => {
    expect(content).toMatch(/COMMENT ON TABLE webhook_endpoints IS/);
    expect(content).toMatch(/COMMENT ON COLUMN webhook_endpoints\.secret_enc IS/);
    expect(content).toMatch(/COMMENT ON COLUMN webhook_endpoints\.secret_iv IS/);
    expect(content).toMatch(/COMMENT ON COLUMN webhook_endpoints\.secret_tag IS/);
    expect(content).not.toMatch(/CREATE TABLE/);
    expect(content).not.toMatch(/ALTER TABLE\s+\S+\s+(ADD|DROP|ALTER)/);
    expect(content).not.toMatch(/\bGRANT\b/);
    expect(content).not.toMatch(/\bCREATE POLICY\b/);
    expect(content).not.toMatch(/\bDROP TABLE\b/);
  });

  test('MIG-030-05 the new COMMENT ON text describes the provider-agnostic secretsProvider abstraction, not a hardcoded env var', () => {
    // The whole point of this migration is to replace the stale claim from
    // migration 016 ("The KEK is QODIQA_KEY_ENCRYPTION_KEY") with the
    // provider-agnostic secretsProvider abstraction. The header comment
    // above the SQL is allowed to quote the old phrase for context; the
    // actual COMMENT ON statements below BEGIN; must not repeat it verbatim.
    const sqlBody = content.slice(content.indexOf('BEGIN;'));
    expect(sqlBody).toMatch(/secretsProvider/);
    expect(sqlBody).not.toMatch(/The KEK is QODIQA_KEY_ENCRYPTION_KEY/);
  });

  test('MIG-030-06 is wrapped in a single BEGIN/COMMIT transaction', () => {
    expect(content).toMatch(/^BEGIN;$/m);
    expect(content).toMatch(/^COMMIT;$/m);
  });

  test('MIG-030-07 records itself in qodiqa_migrations with ON CONFLICT DO NOTHING (idempotent)', () => {
    expect(content).toMatch(/INSERT INTO qodiqa_migrations \(version, name, checksum, applied_by\)/);
    expect(content).toMatch(/VALUES \(30, 'webhook_kek_abstraction_doc_fix'/);
    expect(content).toMatch(/ON CONFLICT \(version\) DO NOTHING;/);
  });
});
