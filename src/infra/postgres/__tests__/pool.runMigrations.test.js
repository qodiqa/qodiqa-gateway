'use strict';

/**
 * Coverage for pool.js's exported runMigrations() —.
 *
 *this export had zero callers (grep confirms) and zero test
 * coverage: it bridges pool.js's own query()/withTransaction() wrappers into
 * migrate.js's runMigrations({ pool }) adapter shape.'s
 * multiInstanceGuard.js now calls it for real, on a genuine startup path
 * (distributed mode's auto-migrate), so this locks down that the bridge
 * actually works — in particular, that a multi-statement migration file
 * (migration 026 itself: BEGIN; ... COMMIT;) is forwarded as a single
 * query() call rather than needing to be split, since node-postgres only
 * supports multi-statement strings via the simple query protocol (no bound
 * parameters) — see pool.js's query(sql, params = [], label) always being
 * called by migrate.js with no params.
 *
 * Strategy: same as pool.isolation.test.js — jest.resetModules() +
 * jest.doMock('pg') with a fake Pool exposing a mocked .query(), so
 * migrate.js's real, unmodified _loadMigrationFiles() reads the actual
 * migrations/ directory from disk but every SQL statement resolves against
 * the mock rather than a real database.
 *
 * runMigrations() runs the whole
 * migrate.js pass inside pool.js's withAdvisoryLock(), which checks out a
 * single dedicated client via _pool.connect() rather than calling
 * _pool.query() directly (see pool.js's withAdvisoryLock()/withTransaction()
 * for why — a session-scoped advisory lock and migrate.js's own per-migration
 * BEGIN/COMMIT must share one connection). The fake Pool's connect() must
 * therefore return a client exposing the same mockPoolQuery — every
 * assertion below still inspects mockPoolQuery.mock.calls exactly as before;
 * only the path those calls travel through changed, not their shape or content.
 */

const fs   = require('fs');
const path = require('path');

const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations');

function loadPool(mockPoolQuery) {
  jest.resetModules();
  process.env.QODIQA_PG_ENABLED = 'true';

  const mockClient = { query: mockPoolQuery, release: jest.fn() };
  jest.doMock('pg', () => ({
    Pool: jest.fn().mockImplementation(() => ({
      query:        mockPoolQuery,
      connect:      jest.fn().mockResolvedValue(mockClient),
      on:           jest.fn(),
      end:          jest.fn().mockResolvedValue(),
      waitingCount: 0,
      options:      { max: 10 },
    })),
  }));
  jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

  const pool = require('../pool');
  pool.initialize();
  return pool;
}

afterEach(() => {
  delete process.env.QODIQA_PG_ENABLED;
});

test('runMigrations() bridges to migrate.js and applies every pending migration file', async () => {
  const mockPoolQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  const pool = loadPool(mockPoolQuery);

  const realFileCount = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => /^\d+_.+\.sql$/.test(f)).length;

  const result = await pool.runMigrations();

  expect(result.applied).toHaveLength(realFileCount);
});

test('migration 026\'s multi-statement SQL (BEGIN;...COMMIT;) is forwarded as a single query() call', async () => {
  const mockPoolQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  const pool = loadPool(mockPoolQuery);

  await pool.runMigrations();

  const migration026Content = fs.readFileSync(
    path.join(MIGRATIONS_DIR, '026_audit_chain_distributed_ordering.sql'), 'utf8'
  );

  const matchingCall = mockPoolQuery.mock.calls.find(([sql]) => sql === migration026Content);
  expect(matchingCall).toBeDefined();
  expect(migration026Content).toContain('BEGIN;');
  expect(migration026Content).toContain('COMMIT;');
});

test('runMigrations() acquires and releases the migration advisory lock around the whole run (finding #2)', async () => {
  const mockPoolQuery = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  const pool = loadPool(mockPoolQuery);

  await pool.runMigrations();

  const calls = mockPoolQuery.mock.calls.map(([sql]) => sql);
  const lockIndex   = calls.findIndex(sql => sql.includes('pg_advisory_lock'));
  const unlockIndex = calls.findIndex(sql => sql.includes('pg_advisory_unlock'));

  expect(lockIndex).toBeGreaterThanOrEqual(0);
  expect(unlockIndex).toBeGreaterThan(lockIndex);
  // Every migration/tracking-table statement must run strictly between the
  // lock and unlock calls — the whole migrate.js pass happens while the
  // lock is held, not just part of it.
  const migrationCreateTableIndex = calls.findIndex(sql => sql.includes('CREATE TABLE IF NOT EXISTS qodiqa_migrations'));
  expect(migrationCreateTableIndex).toBeGreaterThan(lockIndex);
  expect(migrationCreateTableIndex).toBeLessThan(unlockIndex);
});

test('the advisory lock is still released even if migrate.js throws mid-run', async () => {
  // Force a failure by making the checksum-tracking SELECT return a row
  // whose checksum mismatches what the real file on disk hashes to —
  // migrate.js's own integrity guard throws "Migration integrity violation".
  const mockPoolQuery = jest.fn((sql) => {
    if (sql.includes('SELECT version, name, checksum FROM qodiqa_migrations')) {
      return Promise.resolve({ rows: [{ version: 1, name: 'initial_schema', checksum: 'deliberately-wrong-checksum' }], rowCount: 1 });
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
  });
  const pool = loadPool(mockPoolQuery);

  await expect(pool.runMigrations()).rejects.toThrow(/Migration integrity violation/);

  const calls = mockPoolQuery.mock.calls.map(([sql]) => sql);
  expect(calls.some(sql => sql.includes('pg_advisory_lock'))).toBe(true);
  expect(calls.some(sql => sql.includes('pg_advisory_unlock'))).toBe(true);
});

test('already-applied migrations (present in qodiqa_migrations with matching checksum) are skipped', async () => {
  const crypto = require('crypto');
  const files = fs.readdirSync(MIGRATIONS_DIR).filter(f => /^\d+_.+\.sql$/.test(f));
  const appliedRows = files.map(f => {
    const version  = parseInt(f.split('_')[0], 10);
    const content  = fs.readFileSync(path.join(MIGRATIONS_DIR, f), 'utf8');
    const checksum = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    return { version, name: f.replace(/^\d+_/, '').replace(/\.sql$/, ''), checksum };
  });

  const mockPoolQuery = jest.fn((sql) => {
    if (sql.includes('SELECT version, name, checksum FROM qodiqa_migrations')) {
      return Promise.resolve({ rows: appliedRows, rowCount: appliedRows.length });
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
  });
  const pool = loadPool(mockPoolQuery);

  const result = await pool.runMigrations();

  expect(result.applied).toHaveLength(0);
  expect(result.skipped).toBe(files.length);
});
