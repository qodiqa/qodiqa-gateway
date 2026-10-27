'use strict';

/**
 * preflight-runtime.js unit tests, all probes mocked.
 *
 * Each exported check function is tested in isolation (mocked `pg`/`redis`
 * modules, mocked `fetch`, mocked `os.freemem`, and env var manipulation for
 * the keystore-path check) rather than exercising real network/DB calls --
 * a live-service run of the script itself is recorded separately in
 * and
 */

const os = require('os');
const path = require('path');

const SCRIPT_PATH = path.join(__dirname, '..', 'preflight-runtime.js');

describe('checkRedis', () => {
  afterEach(() => { jest.resetModules(); jest.dontMock('redis'); });

  test('ok:true on a successful connect+ping', async () => {
    jest.doMock('redis', () => ({
      createClient: () => ({
        on: jest.fn(),
        connect: jest.fn().mockResolvedValue(),
        ping: jest.fn().mockResolvedValue('PONG'),
        quit: jest.fn().mockResolvedValue(),
      }),
    }), { virtual: true });
    const { checkRedis } = require(SCRIPT_PATH);
    await expect(checkRedis()).resolves.toEqual({ ok: true });
  });

  test('ok:false with a real reason on ECONNREFUSED (AggregateError shape)', async () => {
    const aggErr = new Error('');
    aggErr.name = 'AggregateError';
    aggErr.code = 'ECONNREFUSED';
    aggErr.errors = [{ message: 'connect ECONNREFUSED ::1:6379' }, { message: 'connect ECONNREFUSED 127.0.0.1:6379' }];
    jest.doMock('redis', () => ({
      createClient: () => ({
        on: jest.fn(),
        connect: jest.fn().mockRejectedValue(aggErr),
        destroy: jest.fn(),
      }),
    }), { virtual: true });
    const { checkRedis } = require(SCRIPT_PATH);
    const result = await checkRedis();
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('ECONNREFUSED');
    expect(result.reason).not.toContain('unknown error');
  });

  test('ok:false when the redis module itself is unavailable', async () => {
    jest.doMock('redis', () => { throw new Error('Cannot find module \'redis\''); }, { virtual: true });
    const { checkRedis } = require(SCRIPT_PATH);
    const result = await checkRedis();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/redis module unavailable/);
  });
});

describe('checkPostgresMigrations', () => {
  let readdirSpy;
  afterEach(() => {
    jest.resetModules();
    jest.dontMock('pg');
    if (readdirSpy) readdirSpy.mockRestore();
  });

  test('ok:true when applied equals the migrations directory file count', async () => {
    readdirSpy = jest.spyOn(require('fs'), 'readdirSync')
      .mockReturnValue(Array.from({ length: 999 }, (_, i) => `${i}.sql`));
    jest.doMock('pg', () => ({
      Client: jest.fn().mockImplementation(() => ({
        connect: jest.fn().mockResolvedValue(),
        query: jest.fn().mockResolvedValue({ rows: [{ v: 999 }] }),
        end: jest.fn().mockResolvedValue(),
      })),
    }), { virtual: true });
    const { checkPostgresMigrations } = require(SCRIPT_PATH);
    const result = await checkPostgresMigrations();
    expect(result).toEqual({ ok: true, applied: 999, expected: 999 });
  });

  test('ok:false naming both counts when the database is behind', async () => {
    readdirSpy = jest.spyOn(require('fs'), 'readdirSync')
      .mockReturnValue(Array.from({ length: 56 }, (_, i) => `${i}.sql`));
    jest.doMock('pg', () => ({
      Client: jest.fn().mockImplementation(() => ({
        connect: jest.fn().mockResolvedValue(),
        query: jest.fn().mockResolvedValue({ rows: [{ v: 55 }] }),
        end: jest.fn().mockResolvedValue(),
      })),
    }), { virtual: true });
    const { checkPostgresMigrations } = require(SCRIPT_PATH);
    const result = await checkPostgresMigrations();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/applied 55, expected 56/);
  });

  test('ok:false when postgres is unreachable', async () => {
    readdirSpy = jest.spyOn(require('fs'), 'readdirSync')
      .mockReturnValue(Array.from({ length: 56 }, (_, i) => `${i}.sql`));
    jest.doMock('pg', () => ({
      Client: jest.fn().mockImplementation(() => ({
        connect: jest.fn().mockRejectedValue(new Error('connect ECONNREFUSED')),
        end: jest.fn(),
      })),
    }), { virtual: true });
    const { checkPostgresMigrations } = require(SCRIPT_PATH);
    const result = await checkPostgresMigrations();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/PostgreSQL unreachable/);
  });
});

describe('checkOllama', () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; jest.resetModules(); });

  test('ok:true on HTTP 200', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: true });
    const { checkOllama } = require(SCRIPT_PATH);
    await expect(checkOllama()).resolves.toEqual({ ok: true });
  });

  test('ok:false naming the HTTP status on a non-2xx response', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 404 });
    const { checkOllama } = require(SCRIPT_PATH);
    const result = await checkOllama();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/HTTP 404/);
  });

  test('ok:false when the fetch itself throws (unreachable)', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('fetch failed'));
    const { checkOllama } = require(SCRIPT_PATH);
    const result = await checkOllama();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/Ollama unreachable/);
  });
});

describe('checkKeystorePath', () => {
  let savedEnv;
  beforeEach(() => { savedEnv = { ...process.env }; jest.resetModules(); });
  afterEach(() => { process.env = savedEnv; });

  test('ok:true, skipped, outside production', () => {
    delete process.env.NODE_ENV;
    const { checkKeystorePath } = require(SCRIPT_PATH);
    expect(checkKeystorePath()).toEqual({ ok: true, skipped: 'NODE_ENV is not production' });
  });

  test('ok:false when QODIQA_KEYS_PATH is unset in production', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.QODIQA_KEYS_PATH;
    const { checkKeystorePath } = require(SCRIPT_PATH);
    const result = checkKeystorePath();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/is not set/);
  });

  test('ok:false when QODIQA_KEYS_PATH resolves inside the repo', () => {
    process.env.NODE_ENV = 'production';
    process.env.QODIQA_KEYS_PATH = './data/keys.json';
    const { checkKeystorePath } = require(SCRIPT_PATH);
    const result = checkKeystorePath();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/resolves inside the repo tree/);
  });

  test('ok:true when QODIQA_KEYS_PATH resolves outside the repo', () => {
    process.env.NODE_ENV = 'production';
    process.env.QODIQA_KEYS_PATH = path.join(os.tmpdir(), 'qodiqa-keys-outside-test', 'keys.json');
    const { checkKeystorePath } = require(SCRIPT_PATH);
    expect(checkKeystorePath()).toEqual({ ok: true });
  });
});

describe('checkFreeRam', () => {
  let spy;
  afterEach(() => { if (spy) spy.mockRestore(); jest.resetModules(); });

  test('ok:true above the 6 GB floor', () => {
    spy = jest.spyOn(os, 'freemem').mockReturnValue(34 * 1024 * 1024 * 1024);
    const { checkFreeRam } = require(SCRIPT_PATH);
    const result = checkFreeRam();
    expect(result.ok).toBe(true);
    expect(result.freeGb).toBeCloseTo(34, 0);
  });

  test('ok:false naming the free/floor figures below 6 GB', () => {
    spy = jest.spyOn(os, 'freemem').mockReturnValue(2 * 1024 * 1024 * 1024);
    const { checkFreeRam } = require(SCRIPT_PATH);
    const result = checkFreeRam();
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/2\.0 GB is below the 6 GB/);
  });
});
