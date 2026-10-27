import { MockServer } from '../mock-server';
import { QodiqaClient } from '../../src/index';
import type { Artifact, PortalVerifyResult, PortalVerificationRecord } from '../../src/types';

const MOCK_ARTIFACT: Artifact = {
  expiry: Date.now() + 300_000,
  payload: {
    requestId: 'req-portal',
    requestHash: 'h1',
    policyHash: 'h2',
    tenantId: 't1',
  },
  publicKeyId: 'key-1',
  timestamp: Date.now(),
  signature: 'sig-1',
};

function managementSuccess<T>(data: T) {
  return {
    status: 'success' as const,
    timestamp: '2026-08-14T00:00:00.000Z',
    requestId: 'req-1',
    data,
  };
}

// rewritten to match the real, synchronous
// `POST /v1/portal/verify` contract. There is no async submit/poll model —
// server.mock('POST', '/v1/portal/submit', ...) etc. tested a route that
// never existed.
describe('PortalResource', () => {
  let server: MockServer;
  let baseUrl: string;
  let client: QodiqaClient;

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

  describe('verify()', () => {
    it('returns a complete report in one call, no polling', async () => {
      const report: PortalVerifyResult = {
        verificationId: 'ver-001',
        overallResult: 'VERIFIED',
        failedCheck: null,
        failureReason: null,
        warnings: [],
        checks: [{ check: 'SIGNATURE', result: 'PASS' }],
        metadata: { publicKeyId: 'key-1', timestampMs: 1000, expiryMs: 2000, artifactId: null },
        durationMs: 12,
        verifiedAt: '2026-08-14T00:00:00.000Z',
      };
      server.mock('POST', '/v1/portal/verify', { status: 200, body: managementSuccess(report) });

      const res = await client.portal.verify(MOCK_ARTIFACT);

      expect(res.data.verificationId).toBe('ver-001');
      expect(res.data.overallResult).toBe('VERIFIED');
    });

    it('sends the raw artifact as the request body, not wrapped', async () => {
      const report: PortalVerifyResult = {
        verificationId: 'ver-002',
        overallResult: 'VERIFIED',
        failedCheck: null,
        failureReason: null,
        warnings: [],
        checks: [],
        metadata: { publicKeyId: null, timestampMs: null, expiryMs: null, artifactId: null },
        durationMs: 5,
        verifiedAt: '2026-08-14T00:00:00.000Z',
      };
      server.mock('POST', '/v1/portal/verify', { status: 200, body: managementSuccess(report) });

      await client.portal.verify(MOCK_ARTIFACT);

      const log = server.getCallLog();
      const body = log[0]!.body as Artifact;
      expect(body.signature).toBe('sig-1');
      expect((body as unknown as { artifact?: unknown }).artifact).toBeUndefined();
    });

    it('surfaces a FAILED report as a normal resolved value, not a thrown error', async () => {
      const report: PortalVerifyResult = {
        verificationId: 'ver-003',
        overallResult: 'FAILED',
        failedCheck: 'SIGNATURE',
        failureReason: 'Ed25519 signature does not verify',
        warnings: [],
        checks: [{ check: 'SIGNATURE', result: 'FAIL', reason: 'bad signature' }],
        metadata: { publicKeyId: 'key-1', timestampMs: 1000, expiryMs: 2000, artifactId: null },
        durationMs: 8,
        verifiedAt: '2026-08-14T00:00:00.000Z',
      };
      server.mock('POST', '/v1/portal/verify', { status: 200, body: managementSuccess(report) });

      const res = await client.portal.verify(MOCK_ARTIFACT);

      expect(res.data.overallResult).toBe('FAILED');
      expect(res.data.failedCheck).toBe('SIGNATURE');
    });
  });

  describe('getResult()', () => {
    it('returns the persisted record for a real verificationId', async () => {
      const record: PortalVerificationRecord = {
        id: '1',
        verification_id: 'ver-001',
        artifact_fingerprint: 'f'.repeat(64),
        artifact_public_key_id: 'key-1',
        artifact_timestamp_ms: '1000',
        artifact_expiry_ms: '2000',
        artifact_id: null,
        overall_result: 'VERIFIED',
        checks_performed: [{ check: 'SIGNATURE', result: 'PASS' }],
        failed_check: null,
        failure_reason: null,
        warnings: [],
        transparency_id: null,
        submitted_by: 'public',
        duration_ms: 12,
        verified_at: '2026-08-14T00:00:00.000Z',
      };
      server.mock('GET', '/v1/portal/result/:id', {
        status: 200,
        body: managementSuccess({ verification: record }),
      });

      const res = await client.portal.getResult('ver-001');

      expect(res.data.verification.verification_id).toBe('ver-001');
      expect(res.data.verification.overall_result).toBe('VERIFIED');
    });

    it('throws on empty verificationId', async () => {
      await expect(client.portal.getResult('')).rejects.toThrow();
    });

    it('propagates a 404 when PostgreSQL is disabled (nothing was ever persisted)', async () => {
      server.mock('GET', '/v1/portal/result/:id', {
        status: 404,
        body: {
          status: 'error',
          timestamp: '2026-08-14T00:00:00.000Z',
          requestId: 'req-1',
          error: { code: 'NOT_FOUND', message: 'Verification not found: ver-999' },
        },
      });

      await expect(client.portal.getResult('ver-999')).rejects.toBeInstanceOf(Error);
    });
  });
});
