'use strict';

const { createGatewayClient } = require('../gatewayClient');

const KEY = `sk_${'a'.repeat(32)}`;
const REQUEST = { method: 'POST', path: '/v1/ai/chat', body: { prompt: 'hi' } };

function okFetch(capture) {
  return async (url, init) => {
    capture.push({ url, init });
    return { status: 200, json: async () => ({ artifactId: 'A1', artifact: { payload: {} }, meta: { expiresAt: '2026-10-14T00:01:00.000Z' } }) };
  };
}

describe('demo signer gateway client (R-02)', () => {
  test('calls POST <gateway>/sign with only content-type + authorization, and the exact request + provider', async () => {
    const calls = [];
    const c = createGatewayClient({ gatewayUrl: 'http://gw:3000', timeoutMs: 1000, fetchImpl: okFetch(calls) });
    const out = await c.sign({ key: KEY, request: REQUEST, provider: 'local' });
    expect(out).toEqual({ ok: true, artifactId: 'A1', artifact: { payload: {} }, expiresAt: '2026-10-14T00:01:00.000Z' });
    expect(calls[0].url).toBe('http://gw:3000/sign');
    expect(Object.keys(calls[0].init.headers).sort()).toEqual(['authorization', 'content-type']);
    expect(calls[0].init.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(JSON.parse(calls[0].init.body)).toEqual({ request: REQUEST, payload: { provider: 'local' } });
  });

  test('non-200 → ok:false with the gateway reason, never the key', async () => {
    const c = createGatewayClient({ gatewayUrl: 'http://gw', timeoutMs: 1000,
      fetchImpl: async () => ({ status: 401, json: async () => ({ decision: 'BLOCK', reason: 'SIGNING_IDENTITY_REVOKED' }) }) });
    const out = await c.sign({ key: KEY, request: REQUEST, provider: 'local' });
    expect(out).toEqual({ ok: false, status: 401, reason: 'SIGNING_IDENTITY_REVOKED' });
    expect(JSON.stringify(out)).not.toContain(KEY);
  });

  test('timeout → GATEWAY_TIMEOUT; network error → GATEWAY_UNREACHABLE', async () => {
    const hang = (_u, init) => new Promise((_r, rej) => init.signal.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
    expect(await createGatewayClient({ gatewayUrl: 'http://gw', timeoutMs: 20, fetchImpl: hang }).sign({ key: KEY, request: REQUEST, provider: 'local' }))
      .toEqual({ ok: false, status: null, reason: 'GATEWAY_TIMEOUT' });
    expect(await createGatewayClient({ gatewayUrl: 'http://gw', timeoutMs: 20, fetchImpl: async () => { throw new Error('ECONNREFUSED'); } }).sign({ key: KEY, request: REQUEST, provider: 'local' }))
      .toEqual({ ok: false, status: null, reason: 'GATEWAY_UNREACHABLE' });
  });

  test('200 without an artifact is treated as a failure', async () => {
    const c = createGatewayClient({ gatewayUrl: 'http://gw', timeoutMs: 1000, fetchImpl: async () => ({ status: 200, json: async () => ({}) }) });
    expect((await c.sign({ key: KEY, request: REQUEST, provider: 'local' })).ok).toBe(false);
  });
});
