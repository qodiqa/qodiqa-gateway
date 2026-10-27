'use strict';

/**
 * ER — operator-CLI safety of migrate.js, from the local validation on a faithful LIVE copy:
 *   OA3-F1  --status ignored QODIQA_PG_PORT (silently queried the cluster on 5432).
 *   OA3-F2  the CLI path took no advisory lock (a second concurrent runner raced the first and failed mid-run on a
 *           duplicate key) and set no lock_timeout (a live writer made migration 059 wait without limit).
 * Mocked `pg` Pool (the real migration files are still read): proves the runner's own connection protocol — the
 * advisory lock is taken first on the dedicated client, lock_timeout is set only after it, both are released in
 * order on failure — not PostgreSQL's lock semantics.
 */

const mockQueries = [];
let mockFailOn = null;
const mockPoolConfigs = [];

jest.mock('pg', () => {
  class Pool {
    constructor(cfg) { mockPoolConfigs.push(cfg); }
    on() {}
    async connect() {
      return {
        query: async (sql, params) => {
          mockQueries.push({ sql: String(sql).trim().split('\n')[0].trim(), params });
          if (mockFailOn && mockFailOn.test(String(sql))) { const e = new Error('canceling statement due to lock timeout'); e.code = '55P03'; throw e; }
          if (/SELECT version, name, checksum FROM qodiqa_migrations/.test(sql)) return { rows: [] };
          return { rows: [] };
        },
        release: jest.fn(),
        on() {},
      };
    }
    async query(sql) {
      mockQueries.push({ sql: String(sql).trim().split('\n')[0].trim() });
      return { rows: [] };
    }
    async end() {}
  }
  return { Pool };
});

const migrate = require('../migrate');

const ENV_KEYS = ['QODIQA_PG_MIG_LOCK_TIMEOUT_MS', 'QODIQA_PG_PORT', 'QODIQA_PG_HOST', 'QODIQA_PG_URL'];
let savedEnv;
beforeEach(() => {
  savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  mockQueries.length = 0; mockPoolConfigs.length = 0; mockFailOn = null;
});
afterEach(() => { for (const [k, v] of Object.entries(savedEnv)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

describe('migrate.js operator-CLI safety (ER / OA3-F1, OA3-F2)', () => {
  test('MCS-01 the CLI advisory lock key equals pool.js MIGRATION_ADVISORY_LOCK_KEY (CLI and server auto-migrate serialise together)', () => {
    const pool = jest.requireActual('../pool');
    expect(migrate.MIGRATION_ADVISORY_LOCK_KEY).toBe(946812026);
    expect(pool.MIGRATION_ADVISORY_LOCK_KEY).toBe(migrate.MIGRATION_ADVISORY_LOCK_KEY);
  });

  test('MCS-02 CLI path: advisory lock first, then lock_timeout (default 30000 ms), then the tracking-table bootstrap', async () => {
    await migrate.runMigrations({ dryRun: true });
    const sqls = mockQueries.map((q) => q.sql);
    expect(sqls[0]).toBe('SELECT pg_advisory_lock($1::bigint)');
    expect(mockQueries[0].params).toEqual([946812026]);
    expect(sqls[1]).toBe('SET lock_timeout = 30000');
    expect(sqls[2]).toMatch(/^CREATE TABLE IF NOT EXISTS qodiqa_migrations/);
    expect(sqls).toContain('SELECT pg_advisory_unlock($1::bigint)');
  });

  test('MCS-03 QODIQA_PG_MIG_LOCK_TIMEOUT_MS overrides the default; 0 disables', async () => {
    process.env.QODIQA_PG_MIG_LOCK_TIMEOUT_MS = '5000';
    await migrate.runMigrations({ dryRun: true });
    expect(mockQueries.map((q) => q.sql)).toContain('SET lock_timeout = 5000');
    mockQueries.length = 0;
    process.env.QODIQA_PG_MIG_LOCK_TIMEOUT_MS = '0';
    await migrate.runMigrations({ dryRun: true });
    expect(mockQueries.map((q) => q.sql)).toContain('SET lock_timeout = 0');
  });

  test.each(['-1', '5s', '1.5', 'abc', '30000; DROP TABLE x'])('MCS-04 invalid QODIQA_PG_MIG_LOCK_TIMEOUT_MS %p is refused before any connection', async (bad) => {
    process.env.QODIQA_PG_MIG_LOCK_TIMEOUT_MS = bad;
    await expect(migrate.runMigrations({ dryRun: true })).rejects.toThrow(/QODIQA_PG_MIG_LOCK_TIMEOUT_MS must be a non-negative integer/);
    expect(mockQueries).toHaveLength(0);
  });

  test('MCS-05 a failing migration (lock timeout) rolls back, then releases the advisory lock, then rethrows', async () => {
    mockFailOn = /^\s*(--|BEGIN)/m; // the first migration body
    await expect(migrate.runMigrations()).rejects.toThrow(/lock timeout/);
    const sqls = mockQueries.map((q) => q.sql);
    const rb = sqls.lastIndexOf('ROLLBACK'); const ul = sqls.lastIndexOf('SELECT pg_advisory_unlock($1::bigint)');
    expect(rb).toBeGreaterThan(-1);
    expect(ul).toBeGreaterThan(rb);
  });

  test('MCS-06 an injected pool (server auto-migrate path) is unchanged: no advisory lock or lock_timeout from migrate.js itself', async () => {
    const pool = { query: jest.fn(async () => ({ rows: [] })) };
    await migrate.runMigrations({ pool, dryRun: true });
    const sqls = pool.query.mock.calls.map((c) => String(c[0]));
    expect(sqls.some((s) => /pg_advisory_lock|lock_timeout/.test(s))).toBe(false);
  });

  test('MCS-07 showStatus honours QODIQA_PG_PORT (OA3-F1)', async () => {
    process.env.QODIQA_PG_PORT = '55493';
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try { await migrate.showStatus(); } finally { log.mockRestore(); }
    expect(mockPoolConfigs.at(-1).port).toBe(55493);
  });

  test('MCS-08 showStatus defaults to 5432 when QODIQA_PG_PORT is unset (same default as runMigrations)', async () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try { await migrate.showStatus(); } finally { log.mockRestore(); }
    expect(mockPoolConfigs.at(-1).port).toBe(5432);
  });
});
