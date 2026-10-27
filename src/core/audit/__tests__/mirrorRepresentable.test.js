'use strict';

/**
 * PH16-D3 — an audit entry the PostgreSQL mirror cannot store is refused at append, before
 * anything is persisted, instead of being accepted by the file chain and then permanently stalling the mirror.
 *
 *   MR-D3-01  each bounded field one character over its audit_chain column limit → invalid_<field>, nothing appended
 *   MR-D3-02  exactly at the limit → accepted
 * MR-D3-03 the bound is measured on the mirror projection: 30 non-ASCII characters project to
 *             180 characters and exceed artifact_id VARCHAR(128) even though the raw string is short
 *   MR-D3-04  appendMandatory treats the refusal as non-retryable (no retries, fail closed)
 */

const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../entryBuilder');

const fields = (over = {}) => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH,
  signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, ...over });

describe('PH16-D3 mirror-representable entries only', () => {
  let auditLog;
  beforeAll(() => { auditLog = require('../audit-log'); });
  const count = () => auditLog.memorySnapshot().modernCount;

  test.each([
    ['artifactId', 128], ['tenantId', 128], ['nonce', 256],
  ])('MR-D3-01/02 %s: limit %i accepted, limit+1 refused before anything is appended', async (f, max) => {
    const before = count();
    await expect(auditLog.append(fields({ [f]: 'x'.repeat(max + 1) }))).rejects.toThrow(new RegExp(`^invalid_${f}`));
    expect(count()).toBe(before);
    await expect(auditLog.append(fields({ [f]: 'y'.repeat(max) }))).resolves.toBeTruthy();
    expect(count()).toBe(before + 1);
  });

  test('MR-D3-03 the limit applies to the projected (escaped) form', async () => {
    const before = count();
    await expect(auditLog.append(fields({ artifactId: 'é'.repeat(30) }))).rejects.toThrow(/^invalid_artifactId/);
    expect(count()).toBe(before);
  });

  test('MR-D3-04 appendMandatory fails immediately (non-retryable)', async () => {
    await expect(auditLog.appendMandatory(fields({ nonce: 'n'.repeat(300) }), { maxRetries: 3, retryDelayMs: 1 })).rejects.toThrow(/invalid_nonce/);
  });
});
