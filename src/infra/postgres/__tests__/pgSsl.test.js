'use strict';

// D-D: one PostgreSQL TLS resolution for the app pool, the retention pool and
// the migration runner., migrate.js enabled TLS only for the literal
// QODIQA_PG_SSL=true, so a production migration with QODIQA_PG_SSL unset ran in
// plaintext while the app pool required TLS.

const fs = require('fs');
const os = require('os');
const path = require('path');

const { resolvePgSslOptions } = require('../pgSsl');

describe('resolvePgSslOptions — on/off matrix', () => {
  const cases = [
    // [NODE_ENV, QODIQA_PG_SSL, expected TLS on?]
    ['production', undefined, true],
    ['production', '',        true],   // empty = unset, as in pool.js
    ['production', 'true',    true],
    ['production', 'false',   false],  // explicit opt-out (boot validation refuses it in prod)
    ['development', undefined, false],
    ['development', 'true',   true],
    ['development', 'false',  false],
    ['test',       undefined, false],
    ['production', 'TRUE',    false],  // only the literal 'true' enables when set
  ];
  test.each(cases)('NODE_ENV=%s QODIQA_PG_SSL=%s → TLS %s', (nodeEnv, sslVar, on) => {
    const env = { NODE_ENV: nodeEnv };
    if (sslVar !== undefined) env.QODIQA_PG_SSL = sslVar;
    const r = resolvePgSslOptions(env);
    if (on) expect(r).toEqual({ rejectUnauthorized: true });
    else expect(r).toBe(false);
  });

  test('TLS on reads CA / cert / key from the configured paths', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w2-pgssl-'));
    try {
      for (const n of ['ca', 'cert', 'key']) fs.writeFileSync(path.join(dir, n), `fixture-${n}`);
      const r = resolvePgSslOptions({
        NODE_ENV: 'production',
        QODIQA_PG_SSL_CA: path.join(dir, 'ca'),
        QODIQA_PG_SSL_CERT: path.join(dir, 'cert'),
        QODIQA_PG_SSL_KEY: path.join(dir, 'key'),
      });
      expect(r.rejectUnauthorized).toBe(true);
      expect(r.ca.toString()).toBe('fixture-ca');
      expect(r.cert.toString()).toBe('fixture-cert');
      expect(r.key.toString()).toBe('fixture-key');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('TLS off never touches the certificate paths', () => {
    expect(resolvePgSslOptions({ NODE_ENV: 'development', QODIQA_PG_SSL_CA: '/nonexistent/ca.pem' })).toBe(false);
  });
});

describe('all three PostgreSQL entry points use the shared resolution', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  test.each(['pool.js', 'retentionPool.js', 'migrate.js'])('%s calls resolvePgSslOptions and has no private copy', (f) => {
    const src = read(f);
    expect(src).toMatch(/require\(\s*'\.\/pgSsl'\s*\)/);
    // migrate.js builds both its migrate and --status pools in one factory whose `env`
    // parameter defaults to process.env, so the call reads resolvePgSslOptions(env); the shared resolver is still used.
    expect(src).toMatch(/resolvePgSslOptions\((process\.)?env\)/);
    expect(src).not.toMatch(/QODIQA_PG_SSL\s*===\s*'true'/);
  });
});

describe('migrate.js — production migration connects with TLS when QODIQA_PG_SSL is unset', () => {
  const saved = {};
  const KEYS = ['NODE_ENV', 'QODIQA_PG_SSL', 'QODIQA_PG_SSL_CA', 'QODIQA_PG_SSL_CERT', 'QODIQA_PG_SSL_KEY'];
  beforeEach(() => { for (const k of KEYS) saved[k] = process.env[k]; });
  afterEach(() => {
    for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    jest.resetModules();
    jest.dontMock('pg');
  });

  async function poolOptionsFor(env) {
    for (const k of KEYS) delete process.env[k];
    Object.assign(process.env, env);
    jest.resetModules();
    const captured = [];
    jest.doMock('pg', () => ({
      Pool: jest.fn(function Pool(opts) {
        captured.push(opts);
        this.connect = () => Promise.reject(new Error('w2-test: no connection'));
        this.query = () => Promise.reject(new Error('w2-test: no connection'));
        this.end = () => Promise.resolve();
      }),
    }));
    const { runMigrations } = require('../migrate');
    await expect(runMigrations()).rejects.toThrow('w2-test: no connection');
    expect(captured).toHaveLength(1);
    return captured[0];
  }

  test('NODE_ENV=production, QODIQA_PG_SSL unset → ssl { rejectUnauthorized: true }', async () => {
    const opts = await poolOptionsFor({ NODE_ENV: 'production' });
    expect(opts.ssl).toEqual({ rejectUnauthorized: true });
  });

  test('NODE_ENV=development, QODIQA_PG_SSL unset → ssl false (unchanged)', async () => {
    const opts = await poolOptionsFor({ NODE_ENV: 'development' });
    expect(opts.ssl).toBe(false);
  });
});
