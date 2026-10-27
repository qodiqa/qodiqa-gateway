'use strict';

/**
 * `node src/infra/postgres/migrate.js --status` (showStatus) must connect with the SAME configuration as
 * the migrate path: TLS from QODIQA_PG_SSL* and the client-error guard
 * (pool 'connect' listener that attaches a client 'error' handler). Mocked `pg` Pool records each pool's config
 * and listeners; no database is contacted.
 */

const mockPools = [];

jest.mock('pg', () => {
  class Pool {
    constructor(cfg) { this.cfg = cfg; this.listeners = {}; mockPools.push(this); }
    on(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); return this; }
    async connect() {
      return { query: async () => ({ rows: [] }), release: jest.fn(), on() {} };
    }
    async query() { return { rows: [] }; }
    async end() {}
  }
  return { Pool };
});

const migrate = require('../migrate');

const ENV_KEYS = ['QODIQA_PG_SSL', 'QODIQA_PG_SSL_CA', 'QODIQA_PG_SSL_CERT', 'QODIQA_PG_SSL_KEY', 'NODE_ENV',
  'QODIQA_PG_PORT', 'QODIQA_PG_HOST', 'QODIQA_PG_URL', 'QODIQA_PG_MIG_LOCK_TIMEOUT_MS'];
let saved;
let logSpy;
beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.NODE_ENV = 'test';
  mockPools.length = 0;
  logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => {
  logSpy.mockRestore();
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

async function statusPool() {
  await migrate.showStatus();
  expect(mockPools).toHaveLength(1);
  return mockPools[0];
}

async function migratePool() {
  await migrate.runMigrations({ dryRun: true });
  expect(mockPools.length).toBeGreaterThanOrEqual(1);
  return mockPools[mockPools.length - 1];
}

describe('migrate.js --status uses the migrate path connection config', () => {
  test('MST-01 QODIQA_PG_SSL=true → --status pool has TLS on (rejectUnauthorized), same as the migrate path', async () => {
    process.env.QODIQA_PG_SSL = 'true';
    const s = await statusPool();
    expect(s.cfg.ssl).toEqual({ rejectUnauthorized: true });
    mockPools.length = 0;
    const m = await migratePool();
    expect(s.cfg).toEqual(m.cfg);
  });

  test('MST-02 NODE_ENV=production with no QODIQA_PG_SSL → --status defaults TLS ON (as the migrate path does)', async () => {
    process.env.NODE_ENV = 'production';
    const s = await statusPool();
    expect(s.cfg.ssl).toEqual({ rejectUnauthorized: true });
  });

  test('MST-03 --status pool carries the client-error guard (connect listener)', async () => {
    const s = await statusPool();
    expect(s.__qodiqaClientErrorGuard).toBe(true);
    expect((s.listeners.connect || []).length).toBeGreaterThanOrEqual(1);
    // The connect listener attaches an 'error' handler to each client.
    const clientListeners = {};
    s.listeners.connect[0]({ on(ev, fn) { clientListeners[ev] = fn; } });
    expect(typeof clientListeners.error).toBe('function');
  });

  test('MST-04 control: QODIQA_PG_SSL=false → TLS off on both paths; port still honoured (OA3-F1)', async () => {
    process.env.QODIQA_PG_SSL = 'false';
    process.env.QODIQA_PG_PORT = '55510';
    const s = await statusPool();
    expect(s.cfg.ssl).toBe(false);
    expect(s.cfg.port).toBe(55510);
  });
});
