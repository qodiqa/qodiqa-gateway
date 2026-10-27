'use strict';

const request = require('supertest');
const { createDemoSignerApp } = require('../app');
const { QuotaUnavailableError } = require('../quota');

const KEYS = { allowed: `sk_${'a'.repeat(32)}`, consent_revoked: `sk_${'b'.repeat(32)}`, policy_denied: `sk_${'c'.repeat(32)}` };

function makeConfig(over = {}) {
  const cfg = {
    enabled: true, chatPath: '/v1/ai/chat', provider: 'local', allowedOrigin: 'https://demo.example', trustedProxy: '',
    perIpPerMin: 10, perIpPerDay: 50, globalPerMin: 30, maxPromptChars: 20, scenarios: Object.keys(KEYS), ...over,
  };
  Object.defineProperty(cfg, 'keys', { value: KEYS, enumerable: false });
  Object.defineProperty(cfg, 'ipHashSecret', { value: 's'.repeat(32), enumerable: false });
  return cfg;
}

function setup({ config = makeConfig(), quotaResult = { allowed: true }, quotaError = null, signResult } = {}) {
  const logs = [];
  const signCalls = [];
  const quota = { check: jest.fn(async () => { if (quotaError) throw quotaError; return quotaResult; }) };
  const gatewayClient = { sign: jest.fn(async (args) => { signCalls.push(args); return signResult || { ok: true, artifactId: 'ART-1', artifact: { expiry: 1, payload: { x: 1 }, publicKeyId: 'k', signature: 's', timestamp: 0 }, expiresAt: '2026-10-14T00:01:00.000Z' }; }) };
  const app = createDemoSignerApp({ config, quota, gatewayClient, log: (e) => logs.push(e) });
  return { app, quota, gatewayClient, logs, signCalls };
}

describe('demo signer app (R-02)', () => {
  test('signs exactly {prompt} for POST /v1/ai/chat with the scenario identity and returns the artifact header', async () => {
    const s = setup();
    const res = await request(s.app).post('/v1/demo/sign').send({ scenario: 'consent_revoked', prompt: 'hello' });
    expect(res.status).toBe(200);
    expect(res.body.request).toEqual({ method: 'POST', path: '/v1/ai/chat', body: { prompt: 'hello' } });
    expect(JSON.parse(Buffer.from(res.body.artifactHeader, 'base64').toString('utf8'))).toEqual({ expiry: 1, payload: { x: 1 }, publicKeyId: 'k', signature: 's', timestamp: 0 });
    expect(res.body).toMatchObject({ scenario: 'consent_revoked', artifactId: 'ART-1', expiresAt: '2026-10-14T00:01:00.000Z' });
    expect(s.signCalls[0]).toEqual({ key: KEYS.consent_revoked, request: res.body.request, provider: 'local' });
  });

  test('no key material ever appears in any response or log line', async () => {
    const s = setup();
    const r1 = await request(s.app).post('/v1/demo/sign').send({ scenario: 'allowed', prompt: 'hello' });
    const r2 = await request(s.app).get('/v1/demo/status');
    const r3 = await request(s.app).post('/v1/demo/sign').send({ scenario: 'nope', prompt: 'x' });
    const all = JSON.stringify([r1.body, r1.headers, r2.body, r3.body, s.logs]);
    expect(all).not.toMatch(/sk_/);
    // The prompt is echoed back only inside the signed request body (the browser must send it verbatim);
    // it must never be logged.
    expect(JSON.stringify(s.logs)).not.toContain('hello');
  });

  test.each([
    [{ scenario: 'allowed', prompt: 'x', stream: true }, 'DEMO_FIELD_NOT_ALLOWED'],
    [{ scenario: 'allowed', prompt: 'x', model: 'gpt-4' }, 'DEMO_FIELD_NOT_ALLOWED'],
    [{ scenario: 'allowed', prompt: 'x', extra: 1 }, 'DEMO_INVALID_REQUEST'],
    [{ scenario: 'admin', prompt: 'x' }, 'DEMO_UNKNOWN_SCENARIO'],
    [{ scenario: 'allowed', prompt: '   ' }, 'DEMO_INVALID_PROMPT'],
    [{ scenario: 'allowed', prompt: 'a\u0000b' }, 'DEMO_INVALID_PROMPT'],
    [{ scenario: 'allowed', prompt: 'x'.repeat(21) }, 'DEMO_PROMPT_TOO_LONG'],
    [{ scenario: 'allowed', prompt: 42 }, 'DEMO_INVALID_PROMPT'],
  ])('rejects %j with 400 %s and never reaches quota or gateway', async (body, code) => {
    const s = setup();
    const res = await request(s.app).post('/v1/demo/sign').send(body);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(code);
    expect(s.quota.check).not.toHaveBeenCalled();
    expect(s.gatewayClient.sign).not.toHaveBeenCalled();
  });

  test('prompt limit counts code points (emoji are not double-counted)', async () => {
    const s = setup();
    const res = await request(s.app).post('/v1/demo/sign').send({ scenario: 'allowed', prompt: '😀'.repeat(20) });
    expect(res.status).toBe(200);
  });

  test('malformed JSON → 400; oversized body → 413; neither reaches the gateway', async () => {
    const s = setup();
    const bad = await request(s.app).post('/v1/demo/sign').set('content-type', 'application/json').send('{"scenario":');
    expect(bad.status).toBe(400);
    const big = await request(s.app).post('/v1/demo/sign').send({ scenario: 'allowed', prompt: 'x'.repeat(20000) });
    expect(big.status).toBe(413);
    expect(s.gatewayClient.sign).not.toHaveBeenCalled();
  });

  test('kill switch: disabled → 503 DEMO_DISABLED for every sign request', async () => {
    const s = setup({ config: makeConfig({ enabled: false }) });
    const res = await request(s.app).post('/v1/demo/sign').send({ scenario: 'allowed', prompt: 'x' });
    expect(res.status).toBe(503);
    expect(res.body.error).toBe('DEMO_DISABLED');
    expect((await request(s.app).get('/v1/demo/status')).body.enabled).toBe(false);
  });

  test('quota exceeded → 429 with Retry-After; quota store down → 503 DEMO_QUOTA_UNAVAILABLE (fail-closed)', async () => {
    const over = setup({ quotaResult: { allowed: false, scope: 'global_minute', retryAfterSeconds: 17 } });
    const r1 = await request(over.app).post('/v1/demo/sign').send({ scenario: 'allowed', prompt: 'x' });
    expect(r1.status).toBe(429);
    expect(r1.headers['retry-after']).toBe('17');
    expect(r1.body).toMatchObject({ error: 'DEMO_QUOTA_EXCEEDED', scope: 'global_minute' });
    expect(over.gatewayClient.sign).not.toHaveBeenCalled();

    const down = setup({ quotaError: new QuotaUnavailableError(new Error('ECONNREFUSED')) });
    const r2 = await request(down.app).post('/v1/demo/sign').send({ scenario: 'allowed', prompt: 'x' });
    expect(r2.status).toBe(503);
    expect(r2.body.error).toBe('DEMO_QUOTA_UNAVAILABLE');
    expect(down.gatewayClient.sign).not.toHaveBeenCalled();
  });

  test('gateway refusal → 502 DEMO_SIGN_FAILED with no upstream detail in the response', async () => {
    const s = setup({ signResult: { ok: false, status: 401, reason: 'SIGNING_IDENTITY_REVOKED' } });
    const res = await request(s.app).post('/v1/demo/sign').send({ scenario: 'allowed', prompt: 'x' });
    expect(res.status).toBe(502);
    expect(res.body).toEqual({ error: 'DEMO_SIGN_FAILED' });
    expect(s.logs.find((l) => l.outcome === 'DEMO_SIGN_FAILED')).toMatchObject({ upstreamStatus: 401, upstreamReason: 'SIGNING_IDENTITY_REVOKED' });
  });

  test('client IP for quota: X-Forwarded-For ignored from an untrusted peer; honoured from a trusted proxy', async () => {
    const untrusted = setup();
    await request(untrusted.app).post('/v1/demo/sign').set('x-forwarded-for', '198.51.100.1').send({ scenario: 'allowed', prompt: 'x' });
    await request(untrusted.app).post('/v1/demo/sign').set('x-forwarded-for', '198.51.100.2').send({ scenario: 'allowed', prompt: 'x' });
    const [h1, h2] = untrusted.quota.check.mock.calls.map((c) => c[0]);
    expect(h1).toBe(h2); // spoofed XFF from an untrusted peer cannot mint new quota identities

    const trusted = setup({ config: makeConfig({ trustedProxy: 'loopback' }) });
    await request(trusted.app).post('/v1/demo/sign').set('x-forwarded-for', '198.51.100.1').send({ scenario: 'allowed', prompt: 'x' });
    await request(trusted.app).post('/v1/demo/sign').set('x-forwarded-for', '198.51.100.2').send({ scenario: 'allowed', prompt: 'x' });
    const [t1, t2] = trusted.quota.check.mock.calls.map((c) => c[0]);
    expect(t1).not.toBe(t2);
  });

  test('CORS: only the configured origin; no credentials; Idempotency-Key is not an allowed header', async () => {
    const s = setup();
    const pre = await request(s.app).options('/v1/demo/sign').set('origin', 'https://demo.example');
    expect(pre.status).toBe(204);
    expect(pre.headers['access-control-allow-origin']).toBe('https://demo.example');
    expect(pre.headers['access-control-allow-credentials']).toBeUndefined();
    expect(pre.headers['access-control-allow-headers']).toBe('Content-Type');
    const other = await request(s.app).options('/v1/demo/sign').set('origin', 'https://evil.example');
    expect(other.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('visitor headers (Idempotency-Key, cookies) are never forwarded to the gateway', async () => {
    const s = setup();
    await request(s.app).post('/v1/demo/sign').set('idempotency-key', 'abc').set('cookie', 'a=b').send({ scenario: 'allowed', prompt: 'x' });
    expect(Object.keys(s.signCalls[0]).sort()).toEqual(['key', 'provider', 'request']);
  });

  test('unknown routes → 404; no /v1/ai/chat proxy exists', async () => {
    const s = setup();
    expect((await request(s.app).post('/v1/ai/chat').send({ prompt: 'x' })).status).toBe(404);
    expect((await request(s.app).get('/healthz')).body).toEqual({ ok: true });
  });
});
