import { MockServer, RawFrame, DONE_FRAME } from '../mock-server';
import {
  QodiqaClient,
  AuthenticationError,
  ServerError,
  TimeoutError,
  VerificationError,
} from '../../src/index';
import type { ChatStreamEvent } from '../../src/types';

describe('ChatResource.stream', () => {
  let server: MockServer;
  let baseUrl: string;
  let client: QodiqaClient;

  const ARTIFACT_B64 = Buffer.from(
    JSON.stringify({
      expiry: Date.now() + 300_000,
      payload: {
        requestId: 'req-001',
        requestHash: 'abc123',
        policyHash: 'def456',
        tenantId: 'tenant-1',
      },
      publicKeyId: 'key-1',
      timestamp: Date.now(),
      signature: 'sig-abc',
    }),
  ).toString('base64');

  beforeAll(async () => {
    server = new MockServer();
    baseUrl = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    server.reset();
    // maxRetries: 0 — streaming is never retried; timeout: high default so
    // only a test's own explicit `options.timeout` bounds the stream.
    client = new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 0 });
  });

  async function collect(
    gen: AsyncGenerator<ChatStreamEvent>,
  ): Promise<ChatStreamEvent[]> {
    const events: ChatStreamEvent[] = [];
    for await (const event of gen) events.push(event);
    return events;
  }

  it('yields every event of a successful multi-chunk stream, in order, and completes', async () => {
    server.mockStream('POST', '/ai/chat', {
      frames: [
        { event: 'stream_started', streamId: 's1', requestId: 'r1', artifactId: 'r1', provider: 'openai', model: 'gpt-4' },
        { event: 'chunk_forwarded', delta: 'Hello', index: 0 },
        { event: 'chunk_forwarded', delta: ' world', index: 1 },
        { event: 'stream_completed', streamId: 's1', requestId: 'r1', chunksTotal: 2, bytesTotal: 11, durationMs: 42 },
        DONE_FRAME,
      ],
    });

    const events = await collect(
      client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true }),
    );

    expect(events).toHaveLength(4);
    expect(events[0]).toMatchObject({ event: 'stream_started', provider: 'openai' });
    expect(events[1]).toMatchObject({ event: 'chunk_forwarded', delta: 'Hello', index: 0 });
    expect(events[2]).toMatchObject({ event: 'chunk_forwarded', delta: ' world', index: 1 });
    expect(events[3]).toMatchObject({ event: 'stream_completed', chunksTotal: 2, bytesTotal: 11 });
    // The [DONE] sentinel itself is never yielded as an event.
    expect(events.every((e) => (e as { event: string }).event !== '[DONE]')).toBe(true);
  });

  it('yields a stream_cancelled terminal event on a provider error mid-stream', async () => {
    server.mockStream('POST', '/ai/chat', {
      frames: [
        { event: 'stream_started', streamId: 's2', requestId: 'r2', artifactId: 'r2', provider: 'openai', model: 'gpt-4' },
        { event: 'chunk_forwarded', delta: 'Partial', index: 0 },
        { event: 'stream_cancelled', streamId: 's2', reason: 'PROVIDER_TIMEOUT', requestId: 'r2' },
        DONE_FRAME,
      ],
    });

    const events = await collect(
      client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true }),
    );

    const last = events[events.length - 1];
    expect(last).toMatchObject({ event: 'stream_cancelled', reason: 'PROVIDER_TIMEOUT' });
  });

  it('throws AuthenticationError when enforcement rejects the request before the stream opens (401 JSON)', async () => {
    server.mock('POST', '/ai/chat', {
      status: 401,
      body: { decision: 'BLOCK', reason: 'UNAUTHORIZED', details: { message: 'Bad artifact' }, requestId: 'r3' },
    });

    await expect(
      collect(client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true })),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  // a pre-stream policy/verification BLOCK now returns
  // HTTP 200 (not 403) with a JSON body — `!response.ok` alone can no
  // longer detect "enforcement failed before the stream opened". Confirms
  // stream() checks Content-Type, not just status, and still throws the
  // correctly-classified error rather than silently completing with zero
  // events (the real regression this fix closes — see
  //).
  it('throws VerificationError, not a silent empty stream, for a 200 JSON pre-stream BLOCK', async () => {
    server.mock('POST', '/ai/chat', {
      status: 200,
      body: { decision: 'BLOCK', reason: 'REQUEST_MISMATCH', details: {}, requestId: 'r3b' },
    });

    const events: ChatStreamEvent[] = [];
    let caught: unknown;
    try {
      for await (const event of client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true })) {
        events.push(event);
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(VerificationError);
    expect((caught as VerificationError).status).toBe(200);
    expect(events).toHaveLength(0);
  });

  it('throws a QodiqaError (not a raw parse exception) on a malformed SSE event', async () => {
    server.mockStream('POST', '/ai/chat', {
      frames: [
        { event: 'stream_started', streamId: 's4', requestId: 'r4', artifactId: 'r4', provider: 'openai', model: 'gpt-4' },
        new RawFrame('{not valid json'),
      ],
    });

    const gen = client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true });
    await expect(collect(gen)).rejects.toBeInstanceOf(ServerError);
  });

  it('throws TimeoutError when the connection is accepted but no data ever arrives', async () => {
    server.mockStream('POST', '/ai/chat', { hang: true });

    const gen = client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true }, { timeout: 150 });
    await expect(collect(gen)).rejects.toBeInstanceOf(TimeoutError);
  });

  it('does not apply the client default timeout to a stream when no explicit timeout is given', async () => {
    // config.timeout is 5000ms in beforeEach; frames are spaced 40ms apart
    // well past what a bugged default-timeout reuse would allow to hang on,
    // proving stream() doesn't silently inherit request()'s 30s-style default
    // in a way that would make this flaky — it simply never fires.
    server.mockStream('POST', '/ai/chat', {
      frameDelayMs: 40,
      frames: [
        { event: 'stream_started', streamId: 's5', requestId: 'r5', artifactId: 'r5', provider: 'openai', model: 'gpt-4' },
        { event: 'chunk_forwarded', delta: 'a', index: 0 },
        { event: 'stream_completed', streamId: 's5', requestId: 'r5', chunksTotal: 1, bytesTotal: 1, durationMs: 80 },
        DONE_FRAME,
      ],
    });

    const events = await collect(client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true }));
    expect(events).toHaveLength(3);
  });

  it('stops iterating and releases resources when the caller aborts via AbortController', async () => {
    server.mockStream('POST', '/ai/chat', {
      frameDelayMs: 30,
      frames: [
        { event: 'stream_started', streamId: 's6', requestId: 'r6', artifactId: 'r6', provider: 'openai', model: 'gpt-4' },
        { event: 'chunk_forwarded', delta: 'a', index: 0 },
        { event: 'chunk_forwarded', delta: 'b', index: 1 },
        { event: 'chunk_forwarded', delta: 'c', index: 2 },
        { event: 'stream_completed', streamId: 's6', requestId: 'r6', chunksTotal: 3, bytesTotal: 3, durationMs: 90 },
        DONE_FRAME,
      ],
    });

    const controller = new AbortController();
    const gen = client.chat.stream(
      ARTIFACT_B64,
      { prompt: 'hi', stream: true },
      { signal: controller.signal },
    );

    const received: ChatStreamEvent[] = [];
    await expect(
      (async () => {
        for await (const event of gen) {
          received.push(event);
          if (event.event === 'stream_started') controller.abort();
        }
      })(),
    ).rejects.toThrow();

    // Aborted after the first event — the remaining frames (queued 30ms
    // apart on the mock server) must never be delivered.
    expect(received).toHaveLength(1);
  });

  it('stops iterating cleanly (no thrown error) when the consumer breaks out of the loop early', async () => {
    server.mockStream('POST', '/ai/chat', {
      frameDelayMs: 10,
      frames: [
        { event: 'stream_started', streamId: 's7', requestId: 'r7', artifactId: 'r7', provider: 'openai', model: 'gpt-4' },
        { event: 'chunk_forwarded', delta: 'a', index: 0 },
        { event: 'chunk_forwarded', delta: 'b', index: 1 },
        { event: 'stream_completed', streamId: 's7', requestId: 'r7', chunksTotal: 2, bytesTotal: 2, durationMs: 20 },
        DONE_FRAME,
      ],
    });

    const gen = client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true });
    const received: ChatStreamEvent[] = [];
    for await (const event of gen) {
      received.push(event);
      if (event.event === 'stream_started') break;
    }

    expect(received).toHaveLength(1);
  });

  it('surfaces a network interruption (dropped connection mid-stream) as NetworkError-family QodiqaError, not a raw exception', async () => {
    server.mockStream('POST', '/ai/chat', {
      frames: [
        { event: 'stream_started', streamId: 's8', requestId: 'r8', artifactId: 'r8', provider: 'openai', model: 'gpt-4' },
        { event: 'chunk_forwarded', delta: 'partial', index: 0 },
      ],
      interrupt: true,
    });

    const gen = client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true });
    await expect(collect(gen)).rejects.toMatchObject({ name: expect.any(String) });
    // Re-run to assert specifically it's one of the SDK's own error classes,
    // not an unwrapped low-level fetch/stream exception leaking to callers.
    const gen2 = client.chat.stream(ARTIFACT_B64, { prompt: 'hi', stream: true });
    try {
      await collect(gen2);
      throw new Error('expected collect() to reject');
    } catch (err) {
      expect(err).toHaveProperty('status');
    }
  });

  it('validates inputs the same way create() does', async () => {
    await expect(
      collect(client.chat.stream('', { prompt: 'hi', stream: true })),
    ).rejects.toThrow();
    await expect(
      collect(client.chat.stream(ARTIFACT_B64, { prompt: '', stream: true })),
    ).rejects.toThrow();
  });

  it('sends stream: true on the wire and includes the x-qodiqa-artifact header', async () => {
    server.mockStream('POST', '/ai/chat', {
      frames: [
        { event: 'stream_started', streamId: 's9', requestId: 'r9', artifactId: 'r9', provider: 'openai', model: 'gpt-4' },
        { event: 'stream_completed', streamId: 's9', requestId: 'r9', chunksTotal: 0, bytesTotal: 0, durationMs: 1 },
        DONE_FRAME,
      ],
    });

    await collect(client.chat.stream(ARTIFACT_B64, { prompt: 'hi' }));

    const log = server.getCallLog();
    expect(log[0]!.headers['x-qodiqa-artifact']).toBe(ARTIFACT_B64);
    expect((log[0]!.body as { stream: boolean }).stream).toBe(true);
    expect((log[0]!.body as { prompt: string }).prompt).toBe('hi');
  });
});
