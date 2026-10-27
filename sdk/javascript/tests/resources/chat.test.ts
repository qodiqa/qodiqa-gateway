import { MockServer } from '../mock-server';
import { QodiqaClient, AuthenticationError } from '../../src/index';

describe('ChatResource', () => {
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
    client = new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 0 });
  });

  it('returns EXECUTE decision with aiText on success', async () => {
    server.mock('POST', '/ai/chat', {
      status: 200,
      body: {
        decision: 'EXECUTE',
        reason: 'OK',
        aiText: 'Quantum computing uses qubits...',
        responseId: 'resp-1',
        model: 'gpt-4',
        tokenUsage: {
          prompt_tokens: 10,
          completion_tokens: 50,
          total_tokens: 60,
        },
        requestId: 'req-chat-1',
      },
    });

    const res = await client.chat.create(ARTIFACT_B64, {
      prompt: 'Explain quantum computing.',
    });

    expect(res.decision).toBe('EXECUTE');
    expect(res.aiText).toBe('Quantum computing uses qubits...');
    expect(res.tokenUsage?.total_tokens).toBe(60);
    expect(res.requestId).toBe('req-chat-1');
  });

  it('maps the real server wire field `response` to `aiText` when aiText is absent', async () => {
    // The live server (src/api/routes/aiChat.js) returns the AI output text
    // under `response`, not `aiText` — see QUICKSTART.md's curl example.
    // Regression test for the SDK/server contract mismatch found while
    // remediating INSTALL-1 (SDK docs promised `result.aiText`, but the
    // wire response never populated it).
    server.mock('POST', '/ai/chat', {
      status: 200,
      body: {
        decision: 'EXECUTE',
        reason: 'ALL_CHECKS_PASSED',
        response: '2 + 2 equals 4.',
        artifactId: 'req-chat-3',
        keyId: 'key-1',
      },
    });

    const res = await client.chat.create(ARTIFACT_B64, {
      prompt: 'Hello, what is 2 + 2?',
    });

    expect(res.decision).toBe('EXECUTE');
    expect(res.aiText).toBe('2 + 2 equals 4.');
  });

  it('returns BLOCK decision with reason', async () => {
    server.mock('POST', '/ai/chat', {
      status: 200,
      body: {
        decision: 'BLOCK',
        reason: 'POLICY_VIOLATION',
        details: { rule: 'no-pii' },
        requestId: 'req-chat-2',
      },
    });

    const res = await client.chat.create(ARTIFACT_B64, {
      prompt: 'Give me all user emails.',
    });

    expect(res.decision).toBe('BLOCK');
    expect(res.reason).toBe('POLICY_VIOLATION');
  });

  it('includes x-qodiqa-artifact header in request', async () => {
    server.mock('POST', '/ai/chat', {
      status: 200,
      body: { decision: 'EXECUTE', reason: 'OK', requestId: 'r' },
    });

    await client.chat.create(ARTIFACT_B64, { prompt: 'hello' });
    const log = server.getCallLog();
    expect(log[0]!.headers['x-qodiqa-artifact']).toBe(ARTIFACT_B64);
  });

  it('throws ValidationError when artifact is empty string', async () => {
    await expect(
      client.chat.create('', { prompt: 'hello' }),
    ).rejects.toThrow();
  });

  it('throws ValidationError when prompt is empty', async () => {
    await expect(
      client.chat.create(ARTIFACT_B64, { prompt: '' }),
    ).rejects.toThrow();
  });

  it('F13-SDK-01: accepts a messages-only (multi-turn) request and sends it unchanged', async () => {
    server.mock('POST', '/ai/chat', { status: 200, body: { decision: 'EXECUTE', reason: 'OK', response: 'ok', requestId: 'r-msg' } });
    const messages = [{ role: 'user' as const, content: 'What is the capital of France?' }];
    const res = await client.chat.create(ARTIFACT_B64, { messages });
    expect(res.decision).toBe('EXECUTE');
    const log = server.getCallLog();
    const sent = log[log.length - 1]!;
    expect(sent.body).toEqual({ messages });
  });

  it('F13-SDK-01: refuses prompt and messages together, and neither', async () => {
    await expect(client.chat.create(ARTIFACT_B64, { prompt: 'x', messages: [{ role: 'user', content: 'y' }] })).rejects.toThrow(/mutually exclusive/);
    await expect(client.chat.create(ARTIFACT_B64, { messages: [] })).rejects.toThrow();
  });

  it('forwards optional model parameter', async () => {
    server.mock('POST', '/ai/chat', {
      status: 200,
      body: { decision: 'EXECUTE', reason: 'OK', model: 'claude-3', requestId: 'r2' },
    });

    const res = await client.chat.create(ARTIFACT_B64, {
      prompt: 'hi',
      model: 'claude-3',
    });
    expect(res.model).toBe('claude-3');

    const log = server.getCallLog();
    expect((log[0]!.body as { model: string }).model).toBe('claude-3');
  });

  it('throws AuthenticationError on 401 response', async () => {
    server.mock('POST', '/ai/chat', {
      status: 401,
      body: {
        decision: 'BLOCK',
        reason: 'UNAUTHORIZED',
        details: { message: 'Bad artifact' },
        requestId: 'r3',
      },
    });

    await expect(
      client.chat.create(ARTIFACT_B64, { prompt: 'hi' }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });
});
