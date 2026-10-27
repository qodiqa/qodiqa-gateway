'use strict';

/**
 * (openai 4 -> 7): the SSRF-guarded agent (item 3.8 /) must reach the wire through the REAL openai SDK.
 *
 * openai >= 5 silently ignores the v4 `httpAgent` client option. Every other provider suite mocks the SDK, so with the
 * upgrade alone they all stayed green while a strict-public endpoint resolving to 127.0.0.1 was reached
 *. This suite drives the real SDK against a local
 * stub through baseAdapter.createLazyClient(), which is what every SDK-based adapter uses.
 */

const http = require('http');
const { OpenAI } = require('openai');
const { createLazyClient, guardedFetch } = require('../baseAdapter');
const { createGuardedAgent } = require('../ssrf');

let srv; let port; let hits = 0;
beforeAll((done) => {
  srv = http.createServer((req, res) => {
    hits++;
    if (req.url.includes('/redir/')) { res.writeHead(302, { Location: 'http://169.254.169.254/latest' }); res.end(); return; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: 'x', object: 'chat.completion', choices: [{ index: 0, message: { role: 'assistant', content: 'reached' }, finish_reason: 'stop' }] }));
  });
  srv.listen(0, '127.0.0.1', () => { port = srv.address().port; done(); });
});
afterAll((done) => { srv.close(done); });

const client = (baseURL, env) => createLazyClient({
  resolveConfig: () => ({ apiKey: 'k', baseURL, timeoutMs: 5000, httpAgent: createGuardedAgent(baseURL, env) }),
  OpenAIClass: OpenAI,
}).get();
const ask = (c) => c.chat.completions.create({ model: 'm', messages: [{ role: 'user', content: 'x' }] });

describe('the guarded agent reaches the wire through the real openai SDK', () => {
  test('GF-01 strict-public mode refuses an endpoint that resolves to loopback (the request never arrives)', async () => {
    const before = hits;
    const err = await ask(client(`http://localhost:${port}/v1`, { PROVIDER_GUARD_STRICT_PUBLIC: 'true' })).catch((e) => e);
    expect(err).toBeInstanceOf(OpenAI.APIConnectionError);
    expect(err.cause && err.cause.code).toBe('SSRF_BLOCKED_RESOLVED_ADDRESS');
    expect(hits).toBe(before);
  });

  test('GF-02 the operator-configured local host itself is still reachable in relaxed mode', async () => {
    const r = await ask(client(`http://localhost:${port}/v1`, {}));
    expect(r.choices[0].message.content).toBe('reached');
  });

  test('GF-03 a redirect comes back as a 3xx error and is not followed', async () => {
    const err = await ask(client(`http://localhost:${port}/redir/v1`, {})).catch((e) => e);
    expect(err).toBeInstanceOf(OpenAI.APIError);
    expect(err.status).toBe(302);
  });

  test('GF-04 guardedFetch carries the agent; without an agent it is the plain no-redirect fetch', () => {
    const agent = new http.Agent();
    expect(guardedFetch(agent).guardedAgent).toBe(agent);
    expect(guardedFetch(undefined)).toBe(require('../baseAdapter').noRedirectFetch);
  });
});
