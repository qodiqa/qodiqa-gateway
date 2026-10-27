'use strict';

/**
 * / RT-06 / end-to-end-style verification through the REAL router, the REAL `local` adapter
 * (OpenAI SDK transport) and REAL HTTP, against an IN-PROCESS fake provider (node:http on 127.0.0.1, ephemeral
 * port). Nothing leaves the machine; no real provider is contacted. The fake server counts every request it
 * receives, so "exactly one upstream call" is measured at the socket, not inferred from mocks.
 *
 * A second in-process server stands in for the configured failover target (`llama`), so the suite also proves
 * that an answered 5xx is not re-sent to ANOTHER provider.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));

const http = require('http');

const ENV_KEYS = ['LOCAL_BASE_URL', 'LLAMA_BASE_URL', 'PROVIDER_FAILOVER_LOCAL', 'PROVIDER_RETRY_BASE_MS',
  'PROVIDER_RETRY_JITTER', 'LOCAL_TIMEOUT_MS', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY'];

function startServer(handler) {
  return new Promise((resolve) => {
    const state = { hits: 0, paths: [] };
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (d) => { body += d; });
      req.on('end', () => { state.hits++; state.paths.push(req.url); handler(req, res, body, state); });
    });
    server.listen(0, '127.0.0.1', () => {
      state.baseUrl = `http://127.0.0.1:${server.address().port}/v1`;
      state.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
      resolve(state);
    });
  });
}

function json(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
}

const OK_COMPLETION = {
  id: 'chatcmpl-fake', object: 'chat.completion', created: 1, model: 'fake-model',
  choices: [{ index: 0, message: { role: 'assistant', content: 'from failover' }, finish_reason: 'stop' }],
  usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
};

let primary; let failover; let saved;

beforeEach(async () => {
  saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  jest.resetModules();
});

afterEach(async () => {
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  if (primary) await primary.close();
  if (failover) await failover.close();
  primary = failover = null;
});

async function setup(primaryHandler) {
  primary  = await startServer(primaryHandler);
  failover = await startServer((req, res) => json(res, 200, OK_COMPLETION));
  process.env.LOCAL_BASE_URL          = primary.baseUrl;
  process.env.LLAMA_BASE_URL          = failover.baseUrl;
  process.env.PROVIDER_FAILOVER_LOCAL = 'llama';
  process.env.PROVIDER_RETRY_BASE_MS  = '5';
  process.env.PROVIDER_RETRY_JITTER   = 'false';
  process.env.LOCAL_TIMEOUT_MS        = '5000';
}

const BODY = { model: 'fake-model', messages: [{ role: 'user', content: 'hello' }] };
const META = () => ({ requestId: 'req-rt06', authorizeFailover: async () => ({ ok: true }) });

describe('RT-06 / non-streaming, real HTTP', () => {
  test('provider answers HTTP 500 → exactly ONE upstream call; no same-provider retry, no failover', async () => {
    await setup((req, res) => json(res, 500, { error: { message: 'boom', type: 'server_error' } }));
    const { routeProviderCall } = require('../router');
    const err = await routeProviderCall('local', BODY, META()).catch((e) => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    expect(err.providerMayHaveExecuted).toBe(true);
    expect(primary.hits).toBe(1);
    expect(primary.paths).toEqual(['/v1/chat/completions']);
    expect(failover.hits).toBe(0);
  });

  test('provider answers HTTP 503 → exactly ONE upstream call (any answered 5xx)', async () => {
    await setup((req, res) => json(res, 503, { error: { message: 'unavailable' } }));
    const { routeProviderCall } = require('../router');
    await expect(routeProviderCall('local', BODY, META())).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
    expect(primary.hits).toBe(1);
    expect(failover.hits).toBe(0);
  });

  test('control: HTTP 429 (refused before processing) IS retried once on the same provider, then fails over', async () => {
    await setup((req, res) => json(res, 429, { error: { message: 'slow down', type: 'rate_limit' } }));
    const { routeProviderCall } = require('../router');
    const result = await routeProviderCall('local', BODY, META());
    expect(primary.hits).toBe(2);   // MAX_RETRIES = 1
    expect(failover.hits).toBe(1);  // a 429 is provably unexecuted, so failover is allowed
    expect(result.output).toBe('from failover');
  });

  test('over real HTTP: 404 model-not-found → one call, PROVIDER_INVALID_REQUEST, no failover', async () => {
    await setup((req, res) => json(res, 404, { error: { message: 'model "fake-model" not found' } }));
    const { routeProviderCall } = require('../router');
    await expect(routeProviderCall('local', BODY, META())).rejects.toMatchObject({ code: 'PROVIDER_INVALID_REQUEST' });
    expect(primary.hits).toBe(1);
    expect(failover.hits).toBe(0);
  });
});

describe('RT-06 / streaming, real HTTP', () => {
  async function drain(gen) { const out = []; for await (const c of gen) out.push(c); return out; }

  test('stream request answered HTTP 500 → exactly ONE upstream call, no failover', async () => {
    await setup((req, res) => json(res, 500, { error: { message: 'boom' } }));
    const { routeStreamingProviderCall } = require('../router.stream');
    await expect(drain(routeStreamingProviderCall('local', BODY, META()))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
    expect(primary.hits).toBe(1);
    expect(failover.hits).toBe(0);
  });

  test('stream that emits a chunk and then drops the connection → output kept, failover NOT started', async () => {
    await setup((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(`data: ${JSON.stringify({ id: 'c1', object: 'chat.completion.chunk', created: 1, model: 'fake-model', choices: [{ index: 0, delta: { content: 'partial' }, finish_reason: null }] })}\n\n`);
      setTimeout(() => res.socket.destroy(), 20);
    });
    const { routeStreamingProviderCall } = require('../router.stream');
    const seen = [];
    const err = await (async () => { for await (const c of routeStreamingProviderCall('local', BODY, META())) seen.push(c); })().catch((e) => e);
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(err).toBeInstanceOf(Error);
    expect(err.providerMayHaveExecuted).toBe(true);
    expect(primary.hits).toBe(1);
    expect(failover.hits).toBe(0);
  });
});

// ── truncated streams over the real wire ─────
// RECORDED-CONTRACT SSE WIRE FIXTURES served by the in-process fake provider (no network): the byte shapes follow
// the OpenAI Chat Completions streaming contract that Ollama's /v1 and OpenAI-compatible Llama servers implement —
// `data: {chat.completion.chunk}` frames, finish_reason non-null on the last choice chunk, then `data: [DONE]`.
describe('truncated OpenAI-compatible streams fail over real HTTP (local adapter, real openai SDK)', () => {
  async function drain(gen) { const out = []; for await (const c of gen) out.push(c); return out; }
  const frame = (delta, finish = null) =>
    `data: ${JSON.stringify({ id: 'c1', object: 'chat.completion.chunk', created: 1, model: 'fake-model', choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
  const sse = (body) => (req, res) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.end(body); };

  test('complete wire transcript (finish_reason stop + [DONE]) → success', async () => {
    await setup(sse(frame({ role: 'assistant', content: '' }) + frame({ content: 'Hello' }) + frame({}, 'stop') + 'data: [DONE]\n\n'));
    const { routeStreamingProviderCall } = require('../router.stream');
    await expect(drain(routeStreamingProviderCall('local', BODY, META()))).resolves.toEqual([{ delta: 'Hello' }]);
    expect(primary.hits).toBe(1);
  });

  test('clean connection end after a chunk (no finish_reason, no [DONE]) → error, output kept, no failover', async () => {
    await setup(sse(frame({ role: 'assistant', content: '' }) + frame({ content: 'partial' })));
    const { routeStreamingProviderCall } = require('../router.stream');
    const seen = [];
    const err = await (async () => { for await (const c of routeStreamingProviderCall('local', BODY, META())) seen.push(c); })().catch((e) => e);
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(err).toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    expect(primary.hits).toBe(1);
    expect(failover.hits).toBe(0);
  });

  test('empty 200 stream (no frames at all) → error, and no failover (the request was accepted)', async () => {
    await setup(sse(''));
    const { routeStreamingProviderCall } = require('../router.stream');
    await expect(drain(routeStreamingProviderCall('local', BODY, META()))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    expect(failover.hits).toBe(0);
  });

  test('[DONE] without any finish_reason chunk → error (finish_reason is the only signal the SDK exposes; documented choice)', async () => {
    await setup(sse(frame({ content: 'partial' }) + 'data: [DONE]\n\n'));
    const { routeStreamingProviderCall } = require('../router.stream');
    await expect(drain(routeStreamingProviderCall('local', BODY, META()))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
    expect(failover.hits).toBe(0);
  });
});
