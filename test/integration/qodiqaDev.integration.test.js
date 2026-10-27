'use strict';

/**
 * `qodiqa dev`: the REAL gateway in an isolated environment with the built-in sandbox provider, a disposable PostgreSQL (consent registry) and the Redis of the run.
 * Opt-in: needs Docker and a reachable Redis (REDIS_URL); run with QODIQA_ALLOW_DOCKER_TESTS=true. Everything it starts is stopped at the end.
 *
 *   QD-01 the gateway becomes ready and /sign + /ai/chat work end to end: the answer comes from the sandbox provider and is labelled
 *   QD-02 the demo content rule still refuses its phrase (enforcement is real, not bypassed)
 *   QD-03 the artifact the real gateway signs carries the V1 request hash the SDK middleware (artifact guard) computes for that request
 *   QD-04 no artifact: BLOCK (consent / verification still run)
 */

const crypto = require('crypto');
const net = require('net');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const REDIS_URL = process.env.REDIS_URL || '';
const enabled = process.env.QODIQA_ALLOW_DOCKER_TESTS === 'true' && REDIS_URL !== '' && spawnSync('docker', ['version'], { stdio: 'ignore' }).status === 0;
const run = enabled ? describe : describe.skip;

const freePort = () => new Promise((resolve, reject) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); s.on('error', reject); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

run('qodiqa dev (local sandbox)', () => {
  let child; let out = ''; let port; let key;
  const containers = [];

  beforeAll(async () => {
    port = await freePort();
    child = spawn(process.execPath, [path.join(__dirname, '..', '..', 'scripts', 'dev', 'qodiqa-dev.js'), '--port', String(port), '--redis-url', REDIS_URL, '--no-docker-redis'], { cwd: path.join(__dirname, '..', '..'), env: { ...process.env, NODE_ENV: undefined }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    for (let i = 0; i < 150; i++) {
      try { const r = await fetch(`http://127.0.0.1:${port}/ready`); if (r.status === 200) break; } catch { /* not yet */ }
      if (child.exitCode !== null) throw new Error(`qodiqa dev exited early:\n${out.slice(-2000)}`);
      await sleep(1000);
    }
    const m = /Signing API Key[^\n]*\n(sk_[0-9a-f]+)/.exec(out);
    if (!m) throw new Error(`no signing key in the output:\n${out.slice(-2000)}`);
    key = m[1];
    for (const x of out.matchAll(/disposable (?:PostgreSQL|Redis) container (\S+)/g)) containers.push(x[1]);
  }, 200_000);

  afterAll(async () => {
    if (child && child.exitCode === null) { child.kill(); await sleep(500); }
    for (const c of containers) spawnSync('docker', ['stop', c], { stdio: 'ignore' });
  }, 60_000);

  async function signAndChat(prompt) {
    const body = { prompt };
    const s = await (await fetch(`http://127.0.0.1:${port}/sign`, { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: JSON.stringify({ request: { method: 'POST', path: '/ai/chat', body }, payload: { userId: 'dev-user' }, ttl: 60000 }) })).json();
    const art = Buffer.from(JSON.stringify(s.artifact)).toString('base64');
    const r = await fetch(`http://127.0.0.1:${port}/ai/chat`, { method: 'POST', headers: { 'x-qodiqa-artifact': art, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { signed: s, chat: await r.json(), status: r.status };
  }

  test('QD-01 sign + chat end to end through the real gateway, answered by the sandbox provider', async () => {
    const { chat } = await signAndChat('hello sandbox');
    expect(chat).toMatchObject({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', response: '[sandbox] hello sandbox' });
  }, 60_000);

  test('QD-02 the demo content rule refuses its phrase', async () => {
    const { chat } = await signAndChat('please sandbox-block-me now');
    expect(chat).toMatchObject({ decision: 'BLOCK', reason: 'CONTENT_RULE_BLOCKED' });
    expect(JSON.stringify(chat)).not.toContain('sandbox-block-me');
  }, 60_000);

  test('QD-03 the signed requestHash equals the V1 request hash computed by the SDKs and the artifact guard', async () => {
    const { signed } = await signAndChat('bind me');
    const canonical = JSON.stringify({ body: { prompt: 'bind me' }, method: 'POST', path: '/ai/chat' });
    const expected = crypto.createHash('sha256').update('QODIQA::REQUEST::V1').update(canonical).digest('hex');
    expect(signed.artifact.payload.requestHash).toBe(expected);
  }, 60_000);

  test('QD-04 a request without an artifact is refused', async () => {
    const r = await fetch(`http://127.0.0.1:${port}/ai/chat`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ prompt: 'no artifact' }) });
    const j = await r.json();
    expect(j.decision).toBe('BLOCK');
  }, 30_000);
});
