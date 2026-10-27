'use strict';

// the dedicated cross-tenant role pools. No database —
// pg.Pool is mocked; these pin the fail-closed contract and the target database.

const mockPools = [];
jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation((cfg) => {
    const p = { cfg, query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }), end: jest.fn().mockResolvedValue(undefined), on: jest.fn() };
    mockPools.push(p);
    return p;
  }),
}));
const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...a) => mockEmit(...a) }));

const KEYS = ['QODIQA_PG_ENABLED', 'QODIQA_PG_URL', 'QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_DATABASE',
  'QODIQA_PG_SYSTEM_USER', 'QODIQA_PG_SYSTEM_PASSWORD', 'QODIQA_PG_REPORTING_USER', 'QODIQA_PG_REPORTING_PASSWORD'];
const saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
let rolePools;

beforeEach(() => {
  jest.resetModules();
  mockPools.length = 0; mockEmit.mockClear();
  for (const k of KEYS) delete process.env[k];
  rolePools = require('../rolePools');
});
afterEach(async () => {
  await rolePools.shutdownAll();
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

describe('rolePools — fail closed', () => {
  test('PostgreSQL disabled: query() throws PG_ROLE_POOL_NOT_CONFIGURED; no pool is created', async () => {
    await expect(rolePools.system.query('SELECT 1')).rejects.toMatchObject({ code: 'PG_ROLE_POOL_NOT_CONFIGURED' });
    expect(mockPools).toHaveLength(0);
  });

  test('enabled but the role password is missing: throws, never falls back to the app pool', async () => {
    process.env.QODIQA_PG_ENABLED = 'true';
    await expect(rolePools.reporting.query('SELECT 1')).rejects.toMatchObject({
      code: 'PG_ROLE_POOL_NOT_CONFIGURED', message: expect.stringContaining('QODIQA_PG_REPORTING_PASSWORD'),
    });
    expect(mockPools).toHaveLength(0);
    expect(rolePools.reporting.isConfigured()).toBe(false);
  });

  test('configured: one lazily-created pool per role, as its own role user', async () => {
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_SYSTEM_PASSWORD: 'sys-pw-placeholder', QODIQA_PG_REPORTING_PASSWORD: 'rep-pw-placeholder' });
    await rolePools.system.query('SELECT 1');
    await rolePools.system.query('SELECT 2');
    await rolePools.reporting.query('SELECT 3');
    expect(mockPools).toHaveLength(2);
    expect(mockPools[0].cfg).toMatchObject({ user: 'qodiqa_system', application_name: 'qodiqa-system', database: 'qodiqa' });
    expect(mockPools[1].cfg).toMatchObject({ user: 'qodiqa_reporting', application_name: 'qodiqa-reporting' });
  });
});

describe('rolePools — NF-15: same target database as the app pool', () => {
  test('QODIQA_PG_URL set: the role pool uses THAT URL with only the credentials swapped', async () => {
    Object.assign(process.env, {
      QODIQA_PG_ENABLED: 'true', QODIQA_PG_SYSTEM_PASSWORD: 'p@ss/word',
      QODIQA_PG_URL: 'postgres://qodiqa_app:apppw@db.internal:5433/qodiqa_w5_disposable?sslmode=disable',
    });
    await rolePools.system.query('SELECT 1');
    const u = new URL(mockPools[0].cfg.connectionString);
    expect(u.hostname).toBe('db.internal');
    expect(u.port).toBe('5433');
    expect(u.pathname).toBe('/qodiqa_w5_disposable');
    expect(decodeURIComponent(u.username)).toBe('qodiqa_system');
    expect(decodeURIComponent(u.password)).toBe('p@ss/word');
    expect(u.searchParams.get('sslmode')).toBe('disable');
  });

  test('the INFO event names host/database/user and never the connection string or password', async () => {
    Object.assign(process.env, {
      QODIQA_PG_ENABLED: 'true', QODIQA_PG_SYSTEM_PASSWORD: 'never-log-this-value',
      QODIQA_PG_URL: 'postgres://u:x@h:5432/dbx',
    });
    await rolePools.system.query('SELECT 1');
    const ev = mockEmit.mock.calls.find(([, t]) => t === 'PG_ROLE_POOL_INITIALIZED');
    expect(ev[2]).toEqual({ pool: 'system', host: 'h', database: 'dbx', user: 'qodiqa_system' });
    expect(JSON.stringify(mockEmit.mock.calls)).not.toContain('never-log-this-value');
  });

  test('no URL: host/port/database from QODIQA_PG_*', async () => {
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_REPORTING_PASSWORD: 'x', QODIQA_PG_HOST: 'h2', QODIQA_PG_PORT: '6000', QODIQA_PG_DATABASE: 'dby' });
    await rolePools.reporting.query('SELECT 1');
    expect(mockPools[0].cfg).toMatchObject({ host: 'h2', port: 6000, database: 'dby', user: 'qodiqa_reporting' });
  });
});

test('shutdownAll() ends every created pool; a later query re-creates lazily', async () => {
  Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_SYSTEM_PASSWORD: 'x' });
  await rolePools.system.query('SELECT 1');
  await rolePools.shutdownAll();
  expect(mockPools[0].end).toHaveBeenCalledTimes(1);
  await rolePools.system.query('SELECT 1');
  expect(mockPools).toHaveLength(2);
});

// ── every dedicated role pool has its own circuit breaker ─────────────────────────
describe('rolePools — circuit breaker per pool', () => {
  const OPEN_AFTER = 5; // PG_CB_FAILURE_THRESHOLD default (see pgCircuitBreaker._loadConfig)

  test('CB-01 repeated connection failures open the pool\'s breaker; the next call fast-fails PG_CIRCUIT_OPEN WITHOUT touching the pool', async () => {
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_SYSTEM_PASSWORD = 'pw';
    const refused = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    await rolePools.system.query('SELECT 1').catch(() => {}); // creates the pool
    const pool = mockPools[0];
    pool.query.mockRejectedValue(refused);
    for (let i = 0; i < OPEN_AFTER; i++) await expect(rolePools.system.query('SELECT 1')).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    expect(rolePools.system.breaker.state).toBe('OPEN');
    pool.query.mockClear();
    await expect(rolePools.system.query('SELECT 1')).rejects.toMatchObject({ code: 'PG_CIRCUIT_OPEN' });
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('CB-02 breakers are independent per pool: opening "system" leaves "reporting" closed', async () => {
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_SYSTEM_PASSWORD = 'pw';
    process.env.QODIQA_PG_REPORTING_PASSWORD = 'pw';
    await rolePools.system.query('SELECT 1').catch(() => {});
    mockPools[0].query.mockRejectedValue(Object.assign(new Error('x'), { code: 'ECONNREFUSED' }));
    for (let i = 0; i < OPEN_AFTER; i++) await rolePools.system.query('SELECT 1').catch(() => {});
    expect(rolePools.system.breaker.state).toBe('OPEN');
    expect(rolePools.reporting.breaker.state).toBe('CLOSED');
    await expect(rolePools.reporting.query('SELECT 1')).resolves.toMatchObject({ rowCount: 0 });
  });

  test('CB-03 an application-level SQL error (the server answered) does not trip the breaker', async () => {
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_SYSTEM_PASSWORD = 'pw';
    await rolePools.system.query('SELECT 1').catch(() => {});
    mockPools[0].query.mockRejectedValue(Object.assign(new Error('duplicate key'), { code: '23505' }));
    for (let i = 0; i < OPEN_AFTER + 2; i++) await rolePools.system.query('SELECT 1').catch(() => {});
    expect(rolePools.system.breaker.state).toBe('CLOSED');
  });
});
