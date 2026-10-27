/**
 *API/SDK contract fixes.
 *   P15-01 a server-stated Retry-After is honoured on every retryable error (503 SERVER_OVERLOADED included), a wait
 *          longer than the retry cap or the request budget surfaces the error, and stream() resends a pre-stream
 *          503 SERVER_OVERLOADED (admission refuses before nonce registration) like create() does
 *   P15-02 Retry-After is parsed as delta-seconds or HTTP-date, for every body shape — never NaN
 *   P15-03 a stream body that ends without the terminal [DONE] frame is a NetworkError, not a normal end
 *   P15-04 the flat protocol-limiter 429 body ({error, surface, dimension, reason, retryAfterSeconds}) maps its
 *          `error` code to err.reason; the limiter window name stays in details.blockedBy
 * Evidence:
 */
import * as http from 'http';
import type { AddressInfo } from 'net';
import { QodiqaClient } from '../src/client';
import { NetworkError, RateLimitError, ServerError, TimeoutError } from '../src/errors';
import { parseRetryAfter } from '../src/utils/retry';

const ART = 'ZmFrZS1hcnRpZmFjdA';
const block = (reason: string) => ({ decision: 'BLOCK', reason, details: {}, requestId: '00000000-0000-4000-8000-000000000000' });

type Reply = { status: number; headers?: Record<string, string>; body?: string };
const json = (status: number, body: unknown, headers: Record<string, string> = {}): Reply =>
  ({ status, headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const sse = (frames: string[]): Reply =>
  ({ status: 200, headers: { 'content-type': 'text/event-stream' }, body: frames.map((f) => `data: ${f}\n\n`).join('') });

describe('SDK contract', () => {
  let server: http.Server;
  let baseUrl: string;
  let replies: Reply[] = [];
  let arrivals: number[] = [];

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        arrivals.push(Date.now());
        const r = replies.length > 1 ? replies.shift()! : replies[0]!;
        res.writeHead(r.status, r.headers ?? {});
        res.end(r.body ?? '');
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => { await new Promise<void>((resolve) => server.close(() => resolve())); });
  beforeEach(() => { replies = []; arrivals = []; });

  const client = (o: Record<string, unknown> = {}) =>
    new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 2, apiKey: `ok_${'a'.repeat(64)}`, ...o });
  const http_ = (c: QodiqaClient) => (c as unknown as { http: { get: (p: string) => Promise<unknown> } }).http;

  it('P15-01: create() waits the 503 SERVER_OVERLOADED Retry-After before resending (not the 0-500 ms back-off)', async () => {
    replies = [
      json(503, block('SERVER_OVERLOADED'), { 'retry-after': '1' }),
      json(200, { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', response: 'ok' }),
    ];
    const r = await client().chat.create(ART, { prompt: 'hi' });
    expect(r.decision).toBe('EXECUTE');
    expect(arrivals).toHaveLength(2);
    expect(arrivals[1]! - arrivals[0]!).toBeGreaterThanOrEqual(950);
  });

  it('P15-01: a Retry-After beyond the 30 s retry cap is not retried early; the 503 surfaces at once', async () => {
    replies = [json(503, block('SERVER_OVERLOADED'), { 'retry-after': '3600' })];
    const t0 = Date.now();
    const err = await http_(client()).get('/v1/webhooks').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ServerError);
    expect((err as ServerError).details.retryAfter).toBe(3600);
    expect(arrivals).toHaveLength(1);
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it('P15-01: a wait that would outlive the request timeout surfaces the real 503, not a TimeoutError', async () => {
    replies = [json(503, block('POLICY_UNAVAILABLE'), { 'retry-after': '2' })];
    const err = await http_(client({ timeout: 1500 })).get('/v1/webhooks').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ServerError);
    expect(err).not.toBeInstanceOf(TimeoutError);
    expect((err as ServerError).status).toBe(503);
    expect(arrivals).toHaveLength(1);
  });

  it('P15-01: stream() resends a pre-stream 503 SERVER_OVERLOADED after Retry-After and then streams', async () => {
    replies = [
      json(503, block('SERVER_OVERLOADED'), { 'retry-after': '0' }),
      sse([JSON.stringify({ event: 'stream_started', streamId: 's', requestId: 'r', artifactId: 'r', provider: 'p', model: 'm' }),
        JSON.stringify({ event: 'stream_completed', streamId: 's', requestId: 'r', chunksTotal: 0, bytesTotal: 0, durationMs: 1 }),
        '[DONE]']),
    ];
    const events: unknown[] = [];
    for await (const e of client().chat.stream(ART, { prompt: 'hi', stream: true })) events.push(e);
    expect(events.map((e) => (e as { event: string }).event)).toEqual(['stream_started', 'stream_completed']);
    expect(arrivals).toHaveLength(2);
  });

  it('P15-01: stream() never resends any other pre-stream error (e.g. 503 PROVIDER_UNAVAILABLE)', async () => {
    replies = [json(503, block('PROVIDER_UNAVAILABLE'), { 'retry-after': '0' }), sse(['[DONE]'])];
    const gen = client().chat.stream(ART, { prompt: 'hi', stream: true });
    await expect(gen.next()).rejects.toBeInstanceOf(ServerError);
    expect(arrivals).toHaveLength(1);
  });

  it('P15-02: Retry-After as an HTTP-date, and on a non-JSON (proxy) body, is parsed — never NaN', async () => {
    const future = new Date(Date.now() + 5000).toUTCString();
    replies = [json(429, block('RATE_LIMITED'), { 'retry-after': future })];
    const e1 = await http_(client({ maxRetries: 0 })).get('/x').catch((e: unknown) => e);
    expect(e1).toBeInstanceOf(RateLimitError);
    expect(Number.isFinite((e1 as RateLimitError).retryAfter)).toBe(true);
    expect((e1 as RateLimitError).retryAfter).toBeGreaterThanOrEqual(3);

    replies = [{ status: 503, headers: { 'content-type': 'text/html', 'retry-after': '7' }, body: '<html>busy</html>' }];
    const e2 = await http_(client({ maxRetries: 0 })).get('/x').catch((e: unknown) => e);
    expect(e2).toBeInstanceOf(ServerError);
    expect((e2 as ServerError).details.retryAfter).toBe(7);

    expect(parseRetryAfter('not a date')).toBeUndefined();
    expect(parseRetryAfter('')).toBeUndefined();
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('Thu, 01 Jan 1970 00:00:00 GMT')).toBe(0);
  });

  it('P15-03: a stream that ends without [DONE] is a NetworkError, not a normal end', async () => {
    replies = [sse([
      JSON.stringify({ event: 'stream_started', streamId: 's', requestId: 'r', artifactId: 'r', provider: 'p', model: 'm' }),
      JSON.stringify({ event: 'chunk_forwarded', delta: 'partial', index: 0 }),
    ])];
    const events: unknown[] = [];
    let caught: unknown;
    try {
      for await (const e of client().chat.stream(ART, { prompt: 'hi', stream: true })) events.push(e);
    } catch (e) { caught = e; }
    expect(events).toHaveLength(2);
    expect(caught).toBeInstanceOf(NetworkError);
    expect((caught as Error).message).toMatch(/\[DONE\]/);
  });

  it('P15-04: the flat /sign limiter 429 body maps `error` to err.reason; the window name is details.blockedBy', async () => {
    replies = [json(429, { error: 'RATE_LIMIT_EXCEEDED', surface: 'sign', dimension: 'identity', reason: 'BURST', retryAfterSeconds: 3, requestId: null }, { 'retry-after': '3' })];
    const err = await client({ signToken: 'sk_x', maxRetries: 0 }).sign.sign({
      request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RateLimitError);
    expect((err as RateLimitError).reason).toBe('RATE_LIMIT_EXCEEDED');
    expect((err as RateLimitError).details).toMatchObject({ blockedBy: 'BURST', surface: 'sign', dimension: 'identity', retryAfter: 3 });
    expect((err as RateLimitError).retryAfter).toBe(3);
  });
});
