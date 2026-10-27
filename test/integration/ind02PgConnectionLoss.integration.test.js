'use strict';

/**
 * — abrupt PostgreSQL connection loss while a client
 * is CHECKED OUT must not crash the process; the in-flight work must fail closed and the
 * pool must recover.
 *
 * Real PostgreSQL, reached through a local TCP proxy this test owns (the shared server
 * is never stopped). The proxy destroys every socket mid-query — the same fault the
 * audit's failure harness injected.
 *
 *  1. negative control (child process, unguarded pool): the process DIES with the
 *     uncaught "Connection terminated unexpectedly" — the audit's crash, reproduced;
 *  2. guarded pool (src/infra/postgres/clientErrorGuard.js): the query rejects, nothing
 *     is uncaught, the dead client is discarded, and the pool serves again after recovery;
 *  3. repeated 5× to show it is not a timing accident.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).
const net = require('net');
const path = require('path');
const { spawnSync } = require('child_process');
const { Pool } = require('pg');
const { guardPool, clientErrorCount } = require('../../src/infra/postgres/clientErrorGuard');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_TEST_USER;
const d = REAL_PG ? describe : describe.skip;
const PG_PORT = parseInt(process.env.QODIQA_PG_PORT || '5432', 10);

function startProxy(targetPort) {
  const socks = new Set();
  const srv = net.createServer((c) => {
    const u = net.connect(targetPort, '127.0.0.1');
    socks.add(c); socks.add(u);
    c.pipe(u); u.pipe(c);
    const drop = () => { socks.delete(c); socks.delete(u); c.destroy(); u.destroy(); };
    c.on('error', drop); u.on('error', drop); c.on('close', drop); u.on('close', drop);
  });
  return new Promise((res) => srv.listen(0, '127.0.0.1', () => res({
    port: srv.address().port,
    cut: () => { for (const s of socks) s.destroy(); },
    close: () => new Promise((r) => { for (const s of socks) s.destroy(); srv.close(() => r()); }),
  })));
}

const cfg = (port) => ({ host: '127.0.0.1', port, database: 'postgres', user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD, max: 3 });

d('PostgreSQL connection loss while a client is checked out', () => {
  let proxy;
  beforeAll(async () => { proxy = await startProxy(PG_PORT); });
  afterAll(async () => { if (proxy) await proxy.close(); });

  test('negative control: an UNGUARDED pool crashes the process (the audit defect)', () => {
    const script = `
      const net=require('net');const {Pool}=require('pg');
      const socks=new Set();const srv=net.createServer(c=>{const u=net.connect(${PG_PORT},'127.0.0.1');socks.add(c);socks.add(u);c.pipe(u);u.pipe(c);c.on('error',()=>{});u.on('error',()=>{});});
      srv.listen(0,'127.0.0.1',async()=>{
        const pool=new Pool({host:'127.0.0.1',port:srv.address().port,database:'postgres',user:process.env.U,password:process.env.P,max:1});
        pool.on('error',()=>{});
        const c=await pool.connect();
        c.query('SELECT pg_sleep(5)').catch(()=>{});
        setTimeout(()=>{for(const s of socks)s.destroy();},300);
        setTimeout(()=>{console.log('SURVIVED');process.exit(0);},3000);
      });`;
    const r = spawnSync(process.execPath, ['-e', script], { cwd: path.join(__dirname, '..', '..'), encoding: 'utf8', timeout: 20000,
      env: { ...process.env, U: process.env.QODIQA_PG_TEST_USER, P: process.env.QODIQA_PG_TEST_PASSWORD } });
    expect(r.stdout).not.toContain('SURVIVED');
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/Connection terminated unexpectedly/);
  });

  test.each([1, 2, 3, 4, 5])('guarded pool, run %i: query fails closed, nothing uncaught, pool recovers', async () => {
    const uncaught = [];
    const onUncaught = (e) => uncaught.push(e);
    process.on('uncaughtException', onUncaught);
    const pool = guardPool(new Pool(cfg(proxy.port)), 'ind02-test');
    pool.on('error', () => {}); // idle-client errors were always handled by pg-pool's own listener path
    try {
      const before = clientErrorCount();
      const client = await pool.connect();
      const inflight = client.query('SELECT pg_sleep(5)');
      await new Promise((r) => setTimeout(r, 300));
      proxy.cut();
      await expect(inflight).rejects.toThrow(/Connection terminated|ECONNRESET|terminated/);
      await new Promise((r) => setTimeout(r, 200)); // let the 'end' → 'error' event fire
      client.release();
      expect(clientErrorCount()).toBeGreaterThan(before);
      expect(uncaught).toEqual([]);
      // Recovery: a NEW connection through the (still listening) proxy works; the dead one was discarded.
      const { rows } = await pool.query('SELECT 1 AS ok');
      expect(rows[0].ok).toBe(1);
    } finally {
      process.removeListener('uncaughtException', onUncaught);
      await pool.end();
    }
  }, 30000);
});
