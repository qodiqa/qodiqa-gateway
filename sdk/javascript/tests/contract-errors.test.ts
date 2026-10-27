/**
 *API/SDK contract fixes.
 *   API-02 an artifact rejection is a VerificationError from create() AND stream(), in both server BLOCK modes
 *   API-03 non-idempotent requests are retried only when the server guarantees they were not processed
 *   API-04 operator MFA step-up: typed errors and the otpProvider resend
 */
import { MockServer } from './mock-server';
import { QodiqaClient } from '../src/client';
import {
  AuthenticationError,
  BlockedError,
  MfaEnrollmentRequiredError,
  MfaLockedError,
  MfaRequiredError,
  RateLimitError,
  ServerError,
  VerificationError,
  VERIFICATION_REASONS,
} from '../src/errors';
import { shouldRetryRequest } from '../src/http';

const ART = 'ZmFrZS1hcnRpZmFjdA';
const block = (reason: string) => ({ decision: 'BLOCK', reason, details: {}, requestId: '00000000-0000-4000-8000-000000000000' });

describe('SDK contract', () => {
  let server: MockServer;
  let baseUrl: string;
  beforeAll(async () => { server = new MockServer(); baseUrl = await server.start(); });
  afterAll(async () => { await server.stop(); });
  beforeEach(() => server.reset());

  const client = (o: Record<string, unknown> = {}) =>
    new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 2, apiKey: `ok_${'a'.repeat(64)}`, ...o });

  describe('API-02 create() and stream() classify the same response the same way', () => {
    for (const status of [200, 403]) {
      it(`INVALID_SIGNATURE at HTTP ${status}: both throw VerificationError`, async () => {
        server.mock('POST', '/ai/chat', { status, body: block('INVALID_SIGNATURE') });
        const c = client();
        await expect(c.chat.create(ART, { prompt: 'hi' })).rejects.toBeInstanceOf(VerificationError);
        const it = c.chat.stream(ART, { prompt: 'hi' });
        await expect(it.next()).rejects.toBeInstanceOf(VerificationError);
      });
    }

    it('REPLAY_DETECTED (409 in status mode) and KEY_REVOKED are verification errors', async () => {
      server.mock('POST', '/ai/chat', { status: 409, body: block('REPLAY_DETECTED') });
      await expect(client().chat.create(ART, { prompt: 'hi' })).rejects.toBeInstanceOf(VerificationError);
      server.reset();
      server.mock('POST', '/ai/chat', { status: 200, body: block('KEY_REVOKED') });
      const err = await client().chat.create(ART, { prompt: 'hi' }).catch((e) => e);
      expect(err).toBeInstanceOf(VerificationError);
      expect(err.reason).toBe('KEY_REVOKED');
    });

    it('a policy/consent BLOCK at HTTP 200: create() returns it, stream() throws BlockedError', async () => {
      server.mock('POST', '/ai/chat', { status: 200, body: block('CONSENT_SUSPENDED') });
      const r = await client().chat.create(ART, { prompt: 'hi' });
      expect([r.decision, r.reason]).toEqual(['BLOCK', 'CONSENT_SUSPENDED']);
      const err = await client().chat.stream(ART, { prompt: 'hi' }).next().catch((e) => e);
      expect(err).toBeInstanceOf(BlockedError);
      expect(err.reason).toBe('CONSENT_SUSPENDED');
    });

    it('the verification list covers the server classes (31 reasons)', () => {
      expect(VERIFICATION_REASONS.size).toBe(31);
    });
  });

  describe('API-03 retry policy', () => {
    it('POST /ai/chat 502: NOT resent (the nonce may be consumed)', async () => {
      server.mockSequence('POST', '/ai/chat', [{ status: 502, body: block('PROVIDER_UNAVAILABLE') }, { status: 200, body: { decision: 'EXECUTE' } }]);
      await expect(client({ maxRetries: 2 }).chat.create(ART, { prompt: 'hi' })).rejects.toBeInstanceOf(ServerError);
      expect(server.getCallLog()).toHaveLength(1);
    });

    it('POST /ai/chat 429: NOT resent (per-identity limiter runs after nonce registration)', async () => {
      server.mock('POST', '/ai/chat', { status: 429, body: block('RATE_LIMITED'), headers: { 'retry-after': '0' } });
      await expect(client().chat.create(ART, { prompt: 'hi' })).rejects.toBeInstanceOf(RateLimitError);
      expect(server.getCallLog()).toHaveLength(1);
    });

    it('POST /ai/chat 503 SERVER_OVERLOADED: resent (admission refuses before nonce registration)', async () => {
      server.mockSequence('POST', '/ai/chat', [{ status: 503, body: block('SERVER_OVERLOADED'), headers: { 'retry-after': '0' } }, { status: 200, body: { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', response: 'ok' } }]);
      const r = await client().chat.create(ART, { prompt: 'hi' });
      expect(r.decision).toBe('EXECUTE');
      expect(server.getCallLog()).toHaveLength(2);
    });

    it('predicate: idempotent GET keeps 5xx retries; POST elsewhere retries only 429; MFA_LOCKED never', () => {
      const e = (status: number, reason?: string) => new ServerError('x', { status, reason });
      expect(shouldRetryRequest(e(502), 'GET', '/v1/webhooks')).toBe(true);
      expect(shouldRetryRequest(e(502), 'POST', '/v1/webhooks')).toBe(false);
      expect(shouldRetryRequest(new RateLimitError('x', { status: 429 }), 'POST', '/sign')).toBe(true);
      expect(shouldRetryRequest(new RateLimitError('x', { status: 429 }), 'POST', '/v1/ai/chat')).toBe(false);
      expect(shouldRetryRequest(new MfaLockedError('x', { reason: 'MFA_LOCKED' }), 'GET', '/x')).toBe(false);
    });
  });

  describe('API-04 MFA step-up', () => {
    const mfa = (status: number, code: string) => ({ status, body: { status: 'error', timestamp: 't', requestId: null, error: { code, message: code } } });

    it('typed errors: MFA_REQUIRED/MFA_INVALID → MfaRequiredError (an AuthenticationError); enrollment; locked', async () => {
      server.mock('DELETE', '/v1/webhooks/w1', mfa(401, 'MFA_REQUIRED'));
      const a = await client({ maxRetries: 0 }).webhooks.delete('w1', 'tenant-1').catch((x) => x);
      expect(a).toBeInstanceOf(MfaRequiredError); expect(a).toBeInstanceOf(AuthenticationError);
      server.reset(); server.mock('DELETE', '/v1/webhooks/w1', mfa(403, 'MFA_ENROLLMENT_REQUIRED'));
      expect(await client().webhooks.delete('w1', 'tenant-1').catch((x) => x)).toBeInstanceOf(MfaEnrollmentRequiredError);
      server.reset(); server.mock('DELETE', '/v1/webhooks/w1', mfa(429, 'MFA_LOCKED'));
      expect(await client({ maxRetries: 2 }).webhooks.delete('w1', 'tenant-1').catch((x) => x)).toBeInstanceOf(MfaLockedError);
      expect(server.getCallLog()).toHaveLength(1); // never retried
    });

    it('otpProvider: on MFA_REQUIRED the request is resent ONCE with X-QODIQA-OTP', async () => {
      server.mockSequence('DELETE', '/v1/webhooks/w1', [mfa(401, 'MFA_REQUIRED'), { status: 200, body: { status: 'success', data: {} } }]);
      let calls = 0;
      await client({ otpProvider: () => { calls++; return '123456'; } }).webhooks.delete('w1', 'tenant-1');
      const log = server.getCallLog();
      expect(log).toHaveLength(2);
      expect(log[0]!.headers['x-qodiqa-otp']).toBeUndefined();
      expect(log[1]!.headers['x-qodiqa-otp']).toBe('123456');
      expect(calls).toBe(1);
    });

    it('otpProvider: a wrong code (MFA_INVALID) is surfaced, not looped', async () => {
      server.mockSequence('DELETE', '/v1/webhooks/w1', [mfa(401, 'MFA_REQUIRED'), mfa(401, 'MFA_INVALID')]);
      const err = await client({ otpProvider: () => '000000' }).webhooks.delete('w1', 'tenant-1').catch((x) => x);
      expect(err).toBeInstanceOf(MfaRequiredError); expect(err.reason).toBe('MFA_INVALID');
      expect(server.getCallLog()).toHaveLength(2);
    });
  });

  // 2026-10-06
  describe('', () => {
    const mfa = (status: number, code: string) => ({ status, body: { status: 'error', timestamp: 't', requestId: null, error: { code, message: code } } });

    it('a request carrying X-QODIQA-OTP is never auto-retried (the real 502 surfaces, the code is not replayed)', async () => {
      // Before the fix the call log was [null,"100000","100000"] and the final error MfaRequiredError MFA_INVALID.
      server.mockSequence('DELETE', '/v1/webhooks/w1', [mfa(401, 'MFA_REQUIRED'), { status: 502, body: block('PROVIDER_UNAVAILABLE') }, mfa(401, 'MFA_INVALID')]);
      let calls = 0;
      const err = await client({ maxRetries: 2, otpProvider: () => { calls++; return '100000'; } })
        .webhooks.delete('w1', 'tenant-1').catch((x) => x);
      expect(err).toBeInstanceOf(ServerError);
      expect(err).not.toBeInstanceOf(MfaRequiredError);
      expect(err.status).toBe(502);
      const log = server.getCallLog();
      expect(log.map((e) => e.headers['x-qodiqa-otp'] ?? null)).toEqual([null, '100000']);
      expect(calls).toBe(1);
    });

    it('a caller-supplied X-QODIQA-OTP also disables auto-retry; requests without it keep retrying', async () => {
      server.mockSequence('GET', '/v1/webhooks', [{ status: 502, body: block('X') }, { status: 200, body: { status: 'success', data: [] } }]);
      const http = (client() as unknown as { http: { get: (p: string, o?: unknown) => Promise<unknown> } }).http;
      await expect(http.get('/v1/webhooks', { headers: { 'x-qodiqa-otp': '111111' } })).rejects.toBeInstanceOf(ServerError);
      expect(server.getCallLog()).toHaveLength(1);
      server.reset();
      server.mockSequence('GET', '/v1/webhooks', [{ status: 502, body: block('X') }, { status: 200, body: { status: 'success', data: [] } }]);
      await http.get('/v1/webhooks');
      expect(server.getCallLog()).toHaveLength(2);
    });

    it('the otpProvider wait is not charged against the request timeout (the resend is sent and succeeds)', async () => {
      server.mockSequence('DELETE', '/v1/webhooks/w1', [mfa(401, 'MFA_REQUIRED'), { status: 200, body: { status: 'success', data: {} } }]);
      const slowOtp = () => new Promise<string>((r) => setTimeout(() => r('123456'), 400));
      await client({ timeout: 300, otpProvider: slowOtp }).webhooks.delete('w1', 'tenant-1');
      const log = server.getCallLog();
      expect(log).toHaveLength(2);
      expect(log[1]!.headers['x-qodiqa-otp']).toBe('123456');
    });

    it('chat.create sends Idempotency-Key only when given', async () => {
      server.mock('POST', '/ai/chat', { status: 200, body: { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', response: 'ok' } });
      await client().chat.create(ART, { prompt: 'hi' }, { idempotencyKey: 'idem-123' });
      await client().chat.create(ART, { prompt: 'hi' });
      const log = server.getCallLog();
      expect(log[0]!.headers['idempotency-key']).toBe('idem-123');
      expect(log[1]!.headers['idempotency-key']).toBeUndefined();
      await expect(client().chat.create(ART, { prompt: 'hi' }, { idempotencyKey: ' ' })).rejects.toThrow(/idempotencyKey/);
    });

    it('error requestId falls back to the X-Request-ID response header; a body requestId wins', async () => {
      const rid = '11111111-1111-4111-8111-111111111111';
      server.mock('DELETE', '/v1/webhooks/w1', { status: 503, body: { success: false, error: { code: 'SERVICE_SHUTTING_DOWN', message: 'draining' } }, headers: { 'x-request-id': rid } });
      const a = await client({ maxRetries: 0 }).webhooks.delete('w1', 'tenant-1').catch((x) => x);
      expect(a).toBeInstanceOf(ServerError);
      expect(a.requestId).toBe(rid);
      server.reset();
      server.mock('POST', '/ai/chat', { status: 502, body: block('PROVIDER_RESPONSE_INVALID'), headers: { 'x-request-id': rid } });
      const b = await client().chat.create(ART, { prompt: 'hi' }).catch((x) => x);
      expect(b.requestId).toBe('00000000-0000-4000-8000-000000000000');
    });
  });
});
