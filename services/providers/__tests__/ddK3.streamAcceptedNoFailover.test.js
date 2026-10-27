'use strict';

/**
 * an in-stream provider error BEFORE any output must not trigger streaming failover.
 *
 * Rule: once the provider has ACCEPTED the streaming request (HTTP 2xx,
 * response stream opened), it may already be executing (and billing) the call. Any failure from that point on —
 * an in-band `data: {"error":...}` frame, a dropped connection, a truncated body — is flagged
 * `providerMayHaveExecuted`, so the router never re-sends the call to the failover provider. Failures that
 * provably happen BEFORE acceptance (connection refused, HTTP 429) still fail over (controls below).
 *
 * Real router + real `local` stream adapter (OpenAI SDK transport) + real HTTP against in-process fake servers
 * on 127.0.0.1 (ephemeral ports). The failover target (`llama`) is a second fake server counting requests.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));

const http = require('http');

const ENV_KEYS = ['LOCAL_BASE_URL', 'LLAMA_BASE_URL', 'PROVIDER_FAILOVER_LOCAL', 'PROVIDER_RETRY_BASE_MS',
  'PROVIDER_RETRY_JITTER', 'LOCAL_TIMEOUT_MS', 'LLAMA_TIMEOUT_MS', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
  'GEMINI_API_KEY', 'MISTRAL_API_KEY'];

function startServer(handler) {
  return new Promise((resolve) => {
    const state = { hits: 0 };
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (d) => { body += d; });
      req.on('end', () => { state.hits++; handler(req, res, body, state); });
    });
    server.listen(0, '127.0.0.1', () => {
      state.port    = server.address().port;
      state.baseUrl = `http://127.0.0.1:${state.port}/v1`;
      state.close   = () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
      resolve(state);
    });
  });
}

const chunk = (delta, finish = null) => `data: ${JSON.stringify({
  id: 'c1', object: 'chat.completion.chunk', created: 1, model: 'fake-model',
  choices: [{ index: 0, delta, finish_reason: finish }],
})}\n\n`;

function sseOk(res) {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  res.write(chunk({ content: 'from failover' }));
  res.write(chunk({}, 'stop'));
  res.end('data: [DONE]\n\n');
}

let primary; let failover; let saved;

beforeEach(() => {
  saved = {};
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  jest.resetModules();
});

afterEach(async () => {
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  if (primary && primary.close) await primary.close();
  if (failover) await failover.close();
  primary = failover = null;
});

async function setup(primaryHandler) {
  primary  = await startServer(primaryHandler);
  failover = await startServer((req, res) => sseOk(res));
  process.env.LOCAL_BASE_URL          = primary.baseUrl;
  process.env.LLAMA_BASE_URL          = failover.baseUrl;
  process.env.PROVIDER_FAILOVER_LOCAL = 'llama';
  process.env.PROVIDER_RETRY_BASE_MS  = '5';
  process.env.PROVIDER_RETRY_JITTER   = 'false';
  process.env.LOCAL_TIMEOUT_MS        = '5000';
  process.env.LLAMA_TIMEOUT_MS        = '5000';
}

const BODY = { model: 'fake-model', messages: [{ role: 'user', content: 'hello' }] };
const META = () => ({ requestId: 'req-dd129', authorizeFailover: async () => ({ ok: true }) });

async function run() {
  const { routeStreamingProviderCall } = require('../router.stream');
  const seen = [];
  const err = await (async () => {
    for await (const c of routeStreamingProviderCall('local', BODY, META())) seen.push(c);
  })().catch((e) => e);
  return { seen, err };
}

describe('error after the provider accepted the stream, before any output → no failover', () => {
  test('HTTP 200 then an in-band `data: {"error":...}` frame as the FIRST event → flagged, failover NOT started', async () => {
    await setup((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end(`data: ${JSON.stringify({ error: { message: 'model overloaded', type: 'server_error' } })}\n\n`);
    });
    const { seen, err } = await run();
    expect(seen).toEqual([]);
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    expect(err.providerMayHaveExecuted).toBe(true);
    expect(primary.hits).toBe(1);
    expect(failover.hits).toBe(0);
  });

  test('HTTP 200 then a role-only chunk then an in-band error frame (no text output yet) → no failover', async () => {
    await setup((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write(chunk({ role: 'assistant' }));
      res.end(`data: ${JSON.stringify({ error: { message: 'internal error' } })}\n\n`);
    });
    const { seen, err } = await run();
    expect(seen).toEqual([]);
    expect(err.providerMayHaveExecuted).toBe(true);
    expect(failover.hits).toBe(0);
  });

  test('HTTP 200 headers flushed, then the socket is destroyed before any body byte → no failover', async () => {
    await setup((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.flushHeaders();
      setTimeout(() => res.socket.destroy(), 20);
    });
    const { seen, err } = await run();
    expect(seen).toEqual([]);
    expect(err).toBeInstanceOf(Error);
    expect(err.providerMayHaveExecuted).toBe(true);
    expect(primary.hits).toBe(1);
    expect(failover.hits).toBe(0);
  });
});

describe('controls — failures BEFORE acceptance still fail over', () => {
  test('connection refused (primary never reached) → failover streams the answer', async () => {
    await setup(() => {});
    const deadPort = primary.port;
    await primary.close();
    primary = null;
    process.env.LOCAL_BASE_URL = `http://127.0.0.1:${deadPort}/v1`;
    const { seen, err } = await run();
    expect(err).toBeUndefined();
    expect(seen).toEqual([{ delta: 'from failover' }]);
    expect(failover.hits).toBe(1);
  });

  test('HTTP 429 (refused before processing) → failover streams the answer', async () => {
    await setup((req, res) => {
      res.writeHead(429, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'slow down', type: 'rate_limit' } }));
    });
    const { seen, err } = await run();
    expect(err).toBeUndefined();
    expect(seen).toEqual([{ delta: 'from failover' }]);
    expect(primary.hits).toBeGreaterThanOrEqual(1);
    expect(failover.hits).toBe(1);
  });
});
