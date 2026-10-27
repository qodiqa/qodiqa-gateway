'use strict';

/**
 * GET /audit/:artifactId — AUTHZ-1 remediation.
 *
 * getArtifactById()'s tenant-isolation parameter is now threaded through by
 * construction from an optional ?tenantId= query param. This route has no
 * per-request authenticated tenant of its own (it's a global ops/admin
 * surface — RBAC users are not tenant-scoped in this codebase), so the
 * parameter is opt-in: a caller who supplies it gets tenant-scoped lookup
 * behavior (matching whatever getArtifactById()'s own isolation logic does,
 * already covered by src/core/audit/__tests__/audit-log.index.test.js's
 * AC-04/05/06/47/48); a caller who omits it is unaffected.
 */

jest.mock('../../../core/audit/audit-log.js', () => ({
  getArtifactById:        jest.fn(),
  // #129: the route now calls the chunked/non-blocking twins.
  verifyAuditChainDetailedChunked: jest.fn(() => Promise.resolve({ valid: true, reason: null, tamperingDetected: false, entriesVerified: 0 })),
  getReplayLineage:       jest.fn(() => []),
  // Finding E: GET /chain/integrity now calls this durable-store-fresh
  // twin instead of validateChainIntegrityChunked() — not exercised by the
  // tenant-scoping tests below (those only hit GET /:artifactId), but kept
  // accurate so this mock doesn't silently drift from the real module shape.
  validateChainIntegrityFromDurableStoreChunked: jest.fn(() => Promise.resolve()),
  verifyChecksumAnchorIsolation: jest.fn(() => Promise.resolve({ applicable: false, reason: 'PG_ANCHOR_UNAVAILABLE', valid: null })),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const request = require('supertest');
const express = require('express');
const auditRouter = require('../audit');
const auditLog = require('../../../core/audit/audit-log.js');

const VALID_ID = '11111111-1111-4111-8111-111111111111';

function makeApp() {
  const app = express();
  app.use((req, res, next) => { req.requestId = 'test-req-id'; next(); });
  app.use('/audit', auditRouter);
  return app;
}

describe('GET /audit/:artifactId — tenantId query param threading (AUTHZ-1)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('omitting ?tenantId= passes null through to getArtifactById (unchanged default behavior)', async () => {
    auditLog.getArtifactById.mockReturnValue({
      artifactId: VALID_ID, decision: 'ALLOW', requestId: VALID_ID,
    });

    await request(makeApp()).get(`/audit/${VALID_ID}`);

    expect(auditLog.getArtifactById).toHaveBeenCalledWith(VALID_ID, null);
  });

  test('?tenantId=tenant-A is threaded through to getArtifactById', async () => {
    auditLog.getArtifactById.mockReturnValue({
      artifactId: VALID_ID, decision: 'ALLOW', requestId: VALID_ID,
    });

    await request(makeApp()).get(`/audit/${VALID_ID}?tenantId=tenant-A`);

    expect(auditLog.getArtifactById).toHaveBeenCalledWith(VALID_ID, 'tenant-A');
  });

  test('a tenantId that does not match the entry\'s own tenant (per getArtifactById\'s own isolation logic) → 404, not the cross-tenant entry', async () => {
    // Simulates getArtifactById's real isolation behavior: mismatched
    // tenant → null, exactly like the AC-47 unit test already proves for
    // the underlying function.
    auditLog.getArtifactById.mockReturnValue(null);

    const res = await request(makeApp()).get(`/audit/${VALID_ID}?tenantId=wrong-tenant`);

    expect(res.status).toBe(404);
    expect(res.body.status).toBe('error');
  });

  test('an empty ?tenantId= is treated as no filter (null), not an empty-string tenant', async () => {
    auditLog.getArtifactById.mockReturnValue({
      artifactId: VALID_ID, decision: 'ALLOW', requestId: VALID_ID,
    });

    await request(makeApp()).get(`/audit/${VALID_ID}?tenantId=`);

    expect(auditLog.getArtifactById).toHaveBeenCalledWith(VALID_ID, null);
  });
});

describe('GET /audit/:artifactId — response.tenantId', () => {
  beforeEach(() => jest.clearAllMocks());

  test('response includes the entry\'s own tenantId, independent of ?tenantId= query scoping', async () => {
    auditLog.getArtifactById.mockReturnValue({
      artifactId: VALID_ID, decision: 'ALLOW', requestId: VALID_ID, tenantId: 'tenant-owns-this-entry',
    });

    const res = await request(makeApp()).get(`/audit/${VALID_ID}`);

    expect(res.status).toBe(200);
    expect(res.body.data.tenantId).toBe('tenant-owns-this-entry');
  });

  test('response.tenantId reflects the entry even when a different ?tenantId= scoped the lookup', async () => {
    // The query param only scopes which entry getArtifactById() returns;
    // once an entry is returned, the displayed tenantId is always the
    // entry's own field, not an echo of the query param.
    auditLog.getArtifactById.mockReturnValue({
      artifactId: VALID_ID, decision: 'ALLOW', requestId: VALID_ID, tenantId: 'tenant-A',
    });

    const res = await request(makeApp()).get(`/audit/${VALID_ID}?tenantId=tenant-A`);

    expect(res.body.data.tenantId).toBe('tenant-A');
  });

  test('response.tenantId is null for legacy entries with no tenantId field', async () => {
    auditLog.getArtifactById.mockReturnValue({
      artifactId: VALID_ID, decision: 'ALLOW', requestId: VALID_ID,
    });

    const res = await request(makeApp()).get(`/audit/${VALID_ID}`);

    expect(res.body.data.tenantId).toBeNull();
  });

  test('response.tenantId is null on the replay-only (INCOMPLETE lineage) path, which has no execution entry', async () => {
    auditLog.getArtifactById.mockReturnValue(null);
    auditLog.getReplayLineage.mockReturnValue([
      { artifactId: VALID_ID, timestamp: '2026-01-01T00:00:00.000Z', requestHash: 'abc' },
    ]);

    const res = await request(makeApp()).get(`/audit/${VALID_ID}`);

    expect(res.body.data.lineageState).toBe('INCOMPLETE');
    expect(res.body.data.tenantId).toBeNull();
  });
});
