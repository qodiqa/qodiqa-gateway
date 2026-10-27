'use strict';

/**
 * Launch plan R-08 / H-38: scripts/revoke-signing-identity.js — the out-of-band emergency stop for a public
 * deployment that runs with the admin plane OFF — exercised for real:
 *
 *   one real server.js replica on the PostgreSQL control plane (test/helpers/cluster.js: one disposable database
 *   with the full migration chain, one disposable Redis), then the CLI run as a separate process against the same
 *   control plane, exactly as an operator would via `docker compose exec`.
 *
 * Asserts: CLI exit 0 + status REVOKED (no key material in its output); /sign with the revoked key → 401 within the
 * propagation bound; an artifact minted BEFORE the revocation is refused at /ai/chat with SIGNING_IDENTITY_REVOKED;
 * a second revoke → NO_API_KEY (exit 1); unknown identity → NOT_FOUND (exit 1); missing --reason → usage error (exit 1);
 * re-issuing with provision-signing-identity.js --rotate restores signing, the revoked key never comes back.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI).
const { spawnSync } = require('child_process');
const { startCluster, REPO_ROOT } = require('../helpers/cluster');

const REAL = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_CONTROL_PASSWORD
  && spawnSync('docker', ['info'], { timeout: 20_000 }).status === 0;
const describeOrSkip = REAL ? describe : describe.skip;
jest.setTimeout(600_000);

const BOUND_MS = 5000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describeOrSkip('R-08 revoke-signing-identity CLI against a real replica (PostgreSQL control plane)', () => {
  let c;
  const http = async (method, p, { body, token, headers = {} } = {}) => {
    const res = await fetch(`${c.url('A')}${p}`, {
      method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json = null; try { json = await res.json(); } catch (_) { /* no body */ }
    return { status: res.status, body: json };
  };
  const CHAT_BODY = { prompt: 'Hello from R-08' };
  const CHAT = { method: 'POST', path: '/ai/chat', body: CHAT_BODY };
  const cli = (script, args) => {
    const r = spawnSync(process.execPath, [script, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 90_000, env: c.env() });
    const out = r.stdout || '';
    const i = out.lastIndexOf('\n{');
    let json = null; try { json = JSON.parse((i >= 0 ? out.slice(i + 1) : out).trim()); } catch (_) { /* */ }
    return { code: r.status, json, stdout: out, stderr: r.stderr || '' };
  };
  // /sign probes poll every 700 ms: the /sign auth lockout
  // must not be tripped by the test's own 401 polling; ≤ 8 attempts fit in the 5 s bound.
  async function within(probe, ok, intervalMs = 50) {
    const t0 = Date.now();
    for (;;) {
      const v = await probe();
      if (ok(v)) return Date.now() - t0;
      if (Date.now() - t0 > BOUND_MS) throw new Error(`not in force after ${BOUND_MS} ms; last=${JSON.stringify(v).slice(0, 300)}`);
      await sleep(intervalMs);
    }
  }

  beforeAll(async () => { c = await startCluster({ replicas: 1, tag: 'r08' }); }, 600_000);
  afterAll(async () => { if (c) await c.stop(); }, 120_000);

  test('revoke CLI: REVOKED, /sign 401 within the bound, a pre-minted artifact is refused, re-issue restores signing', async () => {
    const key = c.signing.apiKey;
    // The cluster's Redis was started moments ago. The restart barrier (src/validation/nonceStore.js) refuses any
    // artifact issued within Redis start time + the 5 s future-skew tolerance (REPLAY_STATE_UNPROVABLE, fail-closed,
    // evaluated BEFORE the revocation re-check). Seen once under full-gate load (round1). Sign only after that window.
    await sleep(7000);
    const signed = await http('POST', '/sign', { token: key, body: { request: CHAT, payload: { provider: 'local' } } });
    expect(signed.status).toBe(200);
    const preMinted = { 'x-qodiqa-artifact': Buffer.from(JSON.stringify(signed.body.artifact)).toString('base64') };

    const usage = cli('scripts/revoke-signing-identity.js', ['--name', 'w6-cluster-signer']);
    expect(usage.code).toBe(1);

    const rev = cli('scripts/revoke-signing-identity.js', ['--name', 'w6-cluster-signer', '--reason', 'R-08 emergency stop test', '--by', 'r08-operator']);
    expect(rev.code).toBe(0);
    expect(rev.json).toMatchObject({ status: 'REVOKED', identityId: c.signing.identityId, revokedBy: 'r08-operator' });
    expect(rev.stdout + rev.stderr).not.toContain(key);

    const ms = await within(() => http('POST', '/sign', { token: key, body: { request: CHAT, payload: { provider: 'local' } } }), (r) => r.status === 401, 700);
    expect(ms).toBeLessThanOrEqual(BOUND_MS);

    // One presentation only: the artifact's nonce is consumed on first use, so a retry could only ever be a replay.
    // Revocation is already in force on this replica (the /sign probe above returned 401).
    const chat = await http('POST', '/ai/chat', { headers: preMinted, body: CHAT_BODY });
    expect([chat.body && chat.body.decision, chat.body && chat.body.reason]).toEqual(['BLOCK', 'SIGNING_IDENTITY_REVOKED']);

    const again = cli('scripts/revoke-signing-identity.js', ['--name', 'w6-cluster-signer', '--reason', 'second time']);
    expect([again.code, again.json && again.json.status]).toEqual([1, 'NO_API_KEY']);
    const missing = cli('scripts/revoke-signing-identity.js', ['--name', 'no-such-identity', '--reason', 'x']);
    expect([missing.code, missing.json && missing.json.status]).toEqual([1, 'NOT_FOUND']);

    const rot = cli('scripts/provision-signing-identity.js', ['--name', 'w6-cluster-signer', '--tenant-id', c.clientId, '--environment', 'development', '--rotate']);
    expect(rot.code).toBe(0);
    expect(rot.json && rot.json.status).toBe('ROTATED');
    const fresh = rot.json.apiKey;
    await within(() => http('POST', '/sign', { token: fresh, body: { request: CHAT, payload: { provider: 'local' } } }), (r) => r.status === 200, 700);
    expect((await http('POST', '/sign', { token: key, body: { request: CHAT, payload: { provider: 'local' } } })).status).toBe(401);
  });
});
