'use strict';

/**
 * phase 17 — negative controls for test/helpers/liveEndpointGuard.js (the socket-level backstop that keeps
 * every local test process, and every Node child it spawns, off the LIVE PostgreSQL :5432 / Redis :6379 on the
 * development machine).
 *
 * SAFETY: no test here ever aims a connection at the real 5432/6379. The real-socket proofs use a listener THIS test
 * owns on an ephemeral port, added to the refused set via QODIQA_LIVE_GUARD_EXTRA_PORTS (which can only ADD ports). The
 * 5432/6379 decision itself is proven on the pure predicate (isLiveEndpoint / connectTarget), never on the wire.
 * Children run with CI / QODIQA_TEST_ALLOW_LIVE_PORTS removed so the guard is active even when this suite runs in CI.
 */

const net = require('net');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const guard = require('./helpers/liveEndpointGuard');

const REPO = path.join(__dirname, '..');

function ownListener() {
  return new Promise((resolve) => {
    const accepted = []; const socks = new Set();
    const srv = net.createServer((s) => { accepted.push(s.remoteAddress); socks.add(s); s.on('close', () => socks.delete(s)); s.on('error', () => {}); s.end(); });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port, accepted, socks }));
  });
}

// Child script: tries several client shapes against 127.0.0.1:<port> and prints one RESULT line per attempt.
const CHILD = String.raw`
const net = require('net'); const http = require('http'); const port = Number(process.argv[1]);
const results = {};
function attempt(name, mk) { return new Promise((res) => { let done = false; const fin = (v) => { if (!done) { done = true; results[name] = v; res(); } };
  try { mk(fin); } catch (e) { fin('THROW:' + e.code); } setTimeout(() => fin('TIMEOUT'), 4000); }); }
(async () => {
  await attempt('net.connect(port,host)', (fin) => { const s = net.connect(port, '127.0.0.1'); s.on('connect', () => { s.destroy(); fin('CONNECTED'); }); s.on('error', (e) => fin((e.liveEndpointGuard ? 'GUARD:' : '') + e.code)); });
  await attempt('net.createConnection({host:localhost})', (fin) => { const s = net.createConnection({ port, host: 'localhost' }); s.on('connect', () => { s.destroy(); fin('CONNECTED'); }); s.on('error', (e) => fin((e.liveEndpointGuard ? 'GUARD:' : '') + e.code)); });
  await attempt('new Socket().connect(port)', (fin) => { const s = new net.Socket(); s.on('connect', () => { s.destroy(); fin('CONNECTED'); }); s.on('error', (e) => fin((e.liveEndpointGuard ? 'GUARD:' : '') + e.code)); s.connect(port); });
  await attempt('http.get', (fin) => { const r = http.get({ host: '127.0.0.1', port, path: '/' }, () => fin('CONNECTED')); r.on('error', (e) => fin((e.liveEndpointGuard ? 'GUARD:' : '') + e.code)); });
  await attempt('pg.Client', (fin) => { const { Client } = require('pg'); const c = new Client({ host: '127.0.0.1', port, user: 'x', password: 'x', database: 'x', connectionTimeoutMillis: 3000 });
    c.connect().then(() => fin('CONNECTED'), (e) => fin((e.liveEndpointGuard ? 'GUARD:' : '') + (e.code || e.message))); });
  await attempt('redis.createClient', (fin) => { const { createClient } = require('redis'); const c = createClient({ url: 'redis://127.0.0.1:' + port, socket: { reconnectStrategy: false, connectTimeout: 3000 } });
    c.on('error', () => {}); c.connect().then(() => { fin('CONNECTED'); c.quit().catch(() => {}); }, (e) => fin((e.liveEndpointGuard ? 'GUARD:' : '') + (e.code || e.message))); });
  process.stdout.write('RESULT:' + JSON.stringify(results) + '\n');
  process.exit(0);
})();`;

function cleanEnv(extra) {
  const env = { ...process.env };
  delete env.CI; delete env[guard.ALLOW_FLAG]; delete env[guard.EXTRA_PORTS_VAR]; delete env[guard.LOG_FILE_VAR];
  env.NODE_OPTIONS = String(env.NODE_OPTIONS || '').replace(/--require\s+"?[^"\s]*liveEndpointGuard\.preload\.js"?/g, '').trim();
  return { ...env, ...extra };
}

function runChild(port, env) {
  return new Promise((resolve, reject) => {
    const c = spawn(process.execPath, ['-e', CHILD, String(port)], { cwd: REPO, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { err += d; });
    c.on('error', reject);
    c.on('exit', () => {
      const line = out.split('\n').find((l) => l.startsWith('RESULT:'));
      if (!line) return reject(new Error(`no RESULT line; stdout=${out.slice(-500)} stderr=${err.slice(-800)}`));
      resolve({ results: JSON.parse(line.slice(7)), stderr: err });
    });
  });
}

describe('liveEndpointGuard — the decision (pure; never touches the wire)', () => {
  test('own-host addresses on 5432/6379 are LIVE endpoints; other ports / foreign hosts are not', () => {
    for (const h of ['127.0.0.1', 'localhost', '::1', '[::1]', '127.9.9.9', '0.0.0.0', '', os.hostname()]) {
      expect([h, guard.isLiveEndpoint(h, 5432), guard.isLiveEndpoint(h, 6379)]).toEqual([h, true, true]);
    }
    expect(guard.isLiveEndpoint('127.0.0.1', 55510)).toBe(false);
    expect(guard.isLiveEndpoint('127.0.0.1', 56510)).toBe(false);
    expect(guard.isLiveEndpoint('db.example.invalid', 5432)).toBe(false);
  });

  test('connectTarget understands every Socket#connect call shape (incl. net.connect()\'s normalized array)', () => {
    expect(guard.connectTarget([5432, 'localhost'])).toEqual({ host: 'localhost', port: 5432 });
    expect(guard.connectTarget(['6379'])).toEqual({ host: undefined, port: 6379 });
    expect(guard.connectTarget([{ port: 5432, host: '::1' }])).toEqual({ host: '::1', port: 5432 });
    expect(guard.connectTarget([[{ port: 6379, host: '127.0.0.1' }, () => {}]])).toEqual({ host: '127.0.0.1', port: 6379 });
    expect(guard.connectTarget([{ path: '/tmp/s.sock' }])).toBeNull();
  });

  test('the refused set is always 5432+6379; QODIQA_LIVE_GUARD_EXTRA_PORTS can only add', () => {
    expect(guard.guardedPorts({})).toEqual([5432, 6379]);
    expect(guard.guardedPorts({ [guard.EXTRA_PORTS_VAR]: '41000, junk,0,70000' })).toEqual([5432, 6379, 41000]);
  });

  test('exemption is exactly CI=true or QODIQA_TEST_ALLOW_LIVE_PORTS=true', () => {
    expect(guard.isExempt({})).toBe(false);
    expect(guard.isExempt({ CI: 'false' })).toBe(false);
    expect(guard.isExempt({ CI: 'true' })).toBe(true);
    expect(guard.isExempt({ QODIQA_TEST_ALLOW_LIVE_PORTS: 'true' })).toBe(true);
    expect(guard.isExempt({ QODIQA_TEST_ALLOW_LIVE_PORTS: '1' })).toBe(false);
  });

  test('neutraliseDotenvTargets blanks only the .env-defined target keys the env does not set; explicit values win', () => {
    const parsed = { QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '5432', REDIS_URL: 'redis://localhost:6379', QODIQA_PG_ENABLED: 'true', OPENAI_API_KEY: 'x' };
    const env = { QODIQA_PG_PORT: '55510' };
    const set = guard.neutraliseDotenvTargets(env, { parsed });
    expect(env).toEqual({ QODIQA_PG_PORT: '55510', QODIQA_PG_HOST: '', REDIS_URL: '', QODIQA_PG_ENABLED: 'false' });
    expect(set.sort()).toEqual(['QODIQA_PG_ENABLED', 'QODIQA_PG_HOST', 'REDIS_URL']);
  });

  test('withPreload is idempotent and keeps existing NODE_OPTIONS', () => {
    const once = guard.withPreload('--max-old-space-size=4096');
    expect(once).toMatch(/^--max-old-space-size=4096 --require .*liveEndpointGuard\.preload\.js"?$/);
    expect(guard.withPreload(once)).toBe(once);
  });

  test('optInProblems: explicit non-LIVE host+port required; any LIVE explicit target refused', () => {
    expect(guard.optInProblems({ QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '55510', REDIS_URL: 'redis://127.0.0.1:56510' })).toEqual([]);
    expect(guard.optInProblems({}).join()).toMatch(/no explicit PostgreSQL target/);
    expect(guard.optInProblems({ QODIQA_PG_URL: 'postgres://u:p@127.0.0.1:55510/x' }).join()).toMatch(/no explicit PostgreSQL target/);
    expect(guard.optInProblems({ QODIQA_PG_HOST: 'localhost', QODIQA_PG_PORT: '5432' }).join()).toMatch(/LIVE port/);
    expect(guard.optInProblems({ QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '55510', DATABASE_URL: 'postgres://u@localhost/x' }).join()).toMatch(/DATABASE_URL names localhost:5432/);
    expect(guard.optInProblems({ QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: '55510', REDIS_URL: 'redis://127.0.0.1:6379' }).join()).toMatch(/REDIS_URL 127\.0\.0\.1:6379 is a LIVE port/);
    expect(guard.optInProblems({ CI: 'true' })).toEqual([]);
  });
});

describe('liveEndpointGuard — wiring in this Jest worker (test/support/jest.setup.js)', () => {
  const exempt = guard.isExempt(process.env);

  test('the in-process guard is installed unless exempt', () => {
    expect(!!net.Socket.prototype[Symbol.for('qodiqa.liveEndpointGuard')]).toBe(!exempt);
  });

  test('an env-less child (inherits the worker\'s REAL environment) carries the preload unless exempt', () => {
    const r = spawnSync(process.execPath, ['-e', "process.stdout.write('NO:' + String(process.env.NODE_OPTIONS || ''))"], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(/liveEndpointGuard\.preload\.js/.test(r.stdout)).toBe(!exempt);
  });
});

describe('liveEndpointGuard — real-socket negative controls (own listener, never the LIVE ports)', () => {
  let L; let logDir;
  beforeAll(async () => { L = await ownListener(); logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'live-guard-')); });
  afterAll(async () => { for (const s of L.socks) s.destroy(); await new Promise((r) => L.srv.close(r)); fs.rmSync(logDir, { recursive: true, force: true }); });

  test('POSITIVE CONTROL: without the guard every client shape connects to the listener', async () => {
    const before = L.accepted.length;
    const { results } = await runChild(L.port, cleanEnv({}));
    for (const k of ['net.connect(port,host)', 'net.createConnection({host:localhost})', 'new Socket().connect(port)', 'http.get', 'pg.Client', 'redis.createClient']) {
      expect([k, results[k] === 'CONNECTED' || !/^GUARD:/.test(results[k])]).toEqual([k, true]);
    }
    expect(results['net.connect(port,host)']).toBe('CONNECTED');
    expect(L.accepted.length - before).toBeGreaterThanOrEqual(6);
  });

  test('NEGATIVE CONTROL: with the NODE_OPTIONS preload every client shape is refused and the listener sees ZERO connections', async () => {
    const before = L.accepted.length;
    const log = path.join(logDir, 'blocked.log');
    const { results, stderr } = await runChild(L.port, cleanEnv({
      NODE_OPTIONS: guard.withPreload(''), [guard.EXTRA_PORTS_VAR]: String(L.port), [guard.LOG_FILE_VAR]: log,
    }));
    for (const k of ['net.connect(port,host)', 'net.createConnection({host:localhost})', 'new Socket().connect(port)', 'http.get', 'pg.Client', 'redis.createClient']) {
      expect([k, results[k]]).toEqual([k, expect.stringMatching(/^GUARD:ECONNREFUSED$|^GUARD:/)]);
    }
    expect(L.accepted.length - before).toBe(0);
    expect(stderr).toMatch(new RegExp(`\\[liveEndpointGuard\\] BLOCKED connect to .*:${L.port}`));
    expect(fs.readFileSync(log, 'utf8')).toMatch(new RegExp(`blocked=.*:${L.port}`));
  });

  test('exemptions: CI=true and QODIQA_TEST_ALLOW_LIVE_PORTS=true disable the guard (documented escape hatches)', async () => {
    for (const flag of [{ CI: 'true' }, { [guard.ALLOW_FLAG]: 'true' }]) {
      const before = L.accepted.length;
      const { results } = await runChild(L.port, cleanEnv({ NODE_OPTIONS: guard.withPreload(''), [guard.EXTRA_PORTS_VAR]: String(L.port), ...flag }));
      expect([Object.keys(flag)[0], results['net.connect(port,host)']]).toEqual([Object.keys(flag)[0], 'CONNECTED']);
      expect(L.accepted.length - before).toBeGreaterThanOrEqual(1);
    }
  });

  test('isolatedChildEnv() builds an env that preloads the guard (so a spawned server.js child is covered)', async () => {
    const before = L.accepted.length;
    const env = guard.isolatedChildEnv(cleanEnv({}), { [guard.EXTRA_PORTS_VAR]: String(L.port) });
    const { results } = await runChild(L.port, env);
    expect(results['net.connect(port,host)']).toMatch(/^GUARD:/);
    expect(L.accepted.length - before).toBe(0);
  });
});
