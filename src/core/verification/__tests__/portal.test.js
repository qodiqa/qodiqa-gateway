'use strict';

/**
 * Public Verification Portal Tests — Component #23
 *
 * VP-01 … VP-10   computeArtifactFingerprint (portal.js)
 * VP-11 … VP-30   runPortalChecks — schema/crypto/time failures (portal.js)
 * VP-31 … VP-50   runPortalChecks — advisory checks and passed scenarios (portal.js)
 * VP-51 … VP-65   buildVerificationReport (portal.js)
 * VP-66 … VP-80   portalStore: PG-disabled path (portalStore.js)
 * VP-81 … VP-100  portalStore: PG-enabled path (portalStore.js, mocked pool)
 * VP-101 … VP-110 RBAC permissions matrix
 * VP-121 … VP-128 evidence-chain correlation key (portal.js)
 */

const { createHash, randomUUID } = require('crypto');

// ── Mock pgPool (disabled by default) ─────────────────────────────────────────

const mockPool = {
  _enabled: false,
  isEnabled: function () { return this._enabled; },
  query:     jest.fn(),
};

jest.mock('../../../infra/postgres/pool', () => mockPool);

// ── Mock logger ────────────────────────────────────────────────────────────────

jest.mock('../../../../services/logger', () => ({
  emit:                jest.fn(),
  allowed:             jest.fn(),
  blocked:             jest.fn(),
  eventBus:            { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

// ── Mock validateArtifact ──────────────────────────────────────────────────────

const mockValidateArtifact = jest.fn();
jest.mock('../../../validation/validateArtifact', () => ({
  validateArtifact: mockValidateArtifact,
}));

// ── Mock metrics ───────────────────────────────────────────────────────────────

jest.mock('../../../observability/metrics', () => ({
  portalVerificationsTotal:      { inc: jest.fn() },
  portalVerificationFailuresTotal: { inc: jest.fn() },
  portalPersistFailuresTotal:    { inc: jest.fn() },
}));

// ── Load modules ───────────────────────────────────────────────────────────────

const portal      = require('../portal');
const portalStore = require('../portalStore');
const { PERMISSIONS } = require('../../rbac/roles');

// ── Helpers ────────────────────────────────────────────────────────────────────

const EXECUTE = { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', details: {} };

function blockResult(reason, details = {}) {
  return { decision: 'BLOCK', reason, details };
}

function makeArtifact(overrides = {}) {
  return {
    payload:     { data: 'test', artifactId: 'art-001' },
    signature:   'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    timestamp:   Date.now() - 1000,
    expiry:      Date.now() + 60_000,
    publicKeyId: 'default:key_v1',
    ...overrides,
  };
}

// ── VP-01 … VP-10: computeArtifactFingerprint ─────────────────────────────────

describe('VP-01 … VP-10: computeArtifactFingerprint (portal.js)', () => {
  test('VP-01 returns a 64-char lowercase hex string', () => {
    const fp = portal.computeArtifactFingerprint({ foo: 'bar' });
    expect(typeof fp).toBe('string');
    expect(fp).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(fp)).toBe(true);
  });

  test('VP-02 same input always produces same fingerprint', () => {
    const artifact = makeArtifact();
    const fp1 = portal.computeArtifactFingerprint(artifact);
    const fp2 = portal.computeArtifactFingerprint(artifact);
    expect(fp1).toBe(fp2);
  });

  test('VP-03 different input produces different fingerprint', () => {
    const fp1 = portal.computeArtifactFingerprint({ a: 1 });
    const fp2 = portal.computeArtifactFingerprint({ a: 2 });
    expect(fp1).not.toBe(fp2);
  });

  test('VP-04 key order does not affect fingerprint (canonical)', () => {
    const fp1 = portal.computeArtifactFingerprint({ a: 1, b: 2 });
    const fp2 = portal.computeArtifactFingerprint({ b: 2, a: 1 });
    expect(fp1).toBe(fp2);
  });

  test('VP-05 nested objects produce deterministic fingerprint', () => {
    const artifact = { payload: { x: [1, 2, 3] }, ts: 100 };
    const fp1 = portal.computeArtifactFingerprint(artifact);
    const fp2 = portal.computeArtifactFingerprint(artifact);
    expect(fp1).toBe(fp2);
  });

  test('VP-06 extra field changes fingerprint', () => {
    const base  = makeArtifact();
    const extra = { ...base, extra_field: 'unexpected' };
    expect(portal.computeArtifactFingerprint(base)).not.toBe(
      portal.computeArtifactFingerprint(extra),
    );
  });

  test('VP-07 null value change changes fingerprint', () => {
    const a = { foo: null };
    const b = { foo: 'bar' };
    expect(portal.computeArtifactFingerprint(a)).not.toBe(
      portal.computeArtifactFingerprint(b),
    );
  });

  test('VP-08 empty object has stable fingerprint', () => {
    const fp = portal.computeArtifactFingerprint({});
    expect(fp).toHaveLength(64);
    expect(fp).toBe(portal.computeArtifactFingerprint({}));
  });

  test('VP-09 fingerprint of null input is stable (not throws)', () => {
    const fp = portal.computeArtifactFingerprint(null);
    expect(typeof fp).toBe('string');
    expect(fp).toHaveLength(64);
  });

  test('VP-10 fingerprint matches external SHA-256 of stableStringify', () => {
    const stableStringify = require('../../../../services/utils/stableStringify');
    const artifact = { z: 9, a: 1 };
    const expected = createHash('sha256')
      .update(stableStringify(artifact), 'utf8')
      .digest('hex');
    expect(portal.computeArtifactFingerprint(artifact)).toBe(expected);
  });
});

// ── VP-11 … VP-30: runPortalChecks — core validation failures ─────────────────

describe('VP-11 … VP-30: runPortalChecks — core validation failures (portal.js)', () => {
  beforeEach(() => {
    mockValidateArtifact.mockReset();
  });

  test('VP-11 INVALID_ARTIFACT → SCHEMA fails, rest SKIP', () => {
    mockValidateArtifact.mockReturnValue(blockResult('INVALID_ARTIFACT', { issue: 'missing field' }));
    const result = portal.runPortalChecks({});
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('SCHEMA');
    expect(result.failureReason).toBe('INVALID_ARTIFACT');
    const schemaCheck = result.checks.find(c => c.check === 'SCHEMA');
    expect(schemaCheck.result).toBe('FAIL');
    expect(schemaCheck.reason).toBe('missing field');
    // Checks after SCHEMA should be SKIP
    const after = result.checks.filter(c =>
      ['KEY_VALID', 'TIMESTAMP', 'NOT_EXPIRED', 'SIGNATURE', 'CLOCK_SKEW'].includes(c.check)
    );
    for (const c of after) {
      expect(c.result).toBe('SKIP');
    }
  });

  test('VP-12 KEY_NOT_FOUND → SCHEMA passes, KEY_VALID fails, rest SKIP', () => {
    mockValidateArtifact.mockReturnValue(blockResult('KEY_NOT_FOUND'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('KEY_VALID');
    const schemaCheck = result.checks.find(c => c.check === 'SCHEMA');
    const keyCheck    = result.checks.find(c => c.check === 'KEY_VALID');
    const sigCheck    = result.checks.find(c => c.check === 'SIGNATURE');
    expect(schemaCheck.result).toBe('PASS');
    expect(keyCheck.result).toBe('FAIL');
    expect(sigCheck.result).toBe('SKIP');
  });

  test('VP-13 FUTURE_TIMESTAMP → SCHEMA+KEY_VALID pass, TIMESTAMP fails', () => {
    mockValidateArtifact.mockReturnValue(blockResult('FUTURE_TIMESTAMP'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('TIMESTAMP');
    const tsCheck = result.checks.find(c => c.check === 'TIMESTAMP');
    expect(tsCheck.result).toBe('FAIL');
    const beforeTs = result.checks.filter(c => ['SCHEMA', 'KEY_VALID'].includes(c.check));
    for (const c of beforeTs) {
      expect(c.result).toBe('PASS');
    }
  });

  test('VP-14 EXPIRED → SCHEMA+KEY_VALID+TIMESTAMP pass, NOT_EXPIRED fails', () => {
    mockValidateArtifact.mockReturnValue(blockResult('EXPIRED'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('NOT_EXPIRED');
    const expCheck = result.checks.find(c => c.check === 'NOT_EXPIRED');
    expect(expCheck.result).toBe('FAIL');
    const beforeExp = result.checks.filter(c => ['SCHEMA', 'KEY_VALID', 'TIMESTAMP'].includes(c.check));
    for (const c of beforeExp) {
      expect(c.result).toBe('PASS');
    }
  });

  test('VP-15 INVALID_SIGNATURE → SCHEMA through NOT_EXPIRED pass, SIGNATURE fails', () => {
    mockValidateArtifact.mockReturnValue(blockResult('INVALID_SIGNATURE', { publicKeyId: 'k1' }));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('SIGNATURE');
    const sigCheck   = result.checks.find(c => c.check === 'SIGNATURE');
    const clockCheck = result.checks.find(c => c.check === 'CLOCK_SKEW');
    expect(sigCheck.result).toBe('FAIL');
    expect(clockCheck.result).toBe('SKIP');
  });

  test('VP-16 CLOCK_SKEW_EXCEEDED → SCHEMA through SIGNATURE pass, CLOCK_SKEW fails', () => {
    mockValidateArtifact.mockReturnValue(blockResult('CLOCK_SKEW_EXCEEDED'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('CLOCK_SKEW');
    const clockCheck = result.checks.find(c => c.check === 'CLOCK_SKEW');
    expect(clockCheck.result).toBe('FAIL');
    const before = result.checks.filter(c =>
      ['SCHEMA', 'KEY_VALID', 'TIMESTAMP', 'NOT_EXPIRED', 'SIGNATURE'].includes(c.check)
    );
    for (const c of before) {
      expect(c.result).toBe('PASS');
    }
  });

  test('VP-17 advisory checks are SKIP when core validation fails', () => {
    mockValidateArtifact.mockReturnValue(blockResult('INVALID_ARTIFACT'));
    const result = portal.runPortalChecks(makeArtifact());
    const replayCheck    = result.checks.find(c => c.check === 'REPLAY_CHECK');
    const evidenceCheck  = result.checks.find(c => c.check === 'EVIDENCE_CHAIN');
    expect(replayCheck.result).toBe('SKIP');
    expect(evidenceCheck.result).toBe('SKIP');
  });

  test('VP-18 ARTIFACT_EXPIRED maps to NOT_EXPIRED (alias reason)', () => {
    mockValidateArtifact.mockReturnValue(blockResult('ARTIFACT_EXPIRED'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.failedCheck).toBe('NOT_EXPIRED');
  });

  test('VP-19 ARTIFACT_STALE maps to NOT_EXPIRED (alias reason)', () => {
    mockValidateArtifact.mockReturnValue(blockResult('ARTIFACT_STALE'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.failedCheck).toBe('NOT_EXPIRED');
  });

  test('VP-20 unknown block reason falls back to SCHEMA', () => {
    mockValidateArtifact.mockReturnValue(blockResult('TOTALLY_UNKNOWN_REASON'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.failedCheck).toBe('SCHEMA');
  });

  test('VP-21 SIGNATURE_INVALID alias maps to SIGNATURE', () => {
    mockValidateArtifact.mockReturnValue(blockResult('SIGNATURE_INVALID'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.failedCheck).toBe('SIGNATURE');
  });

  test('VP-22 PUBLIC_KEY_NOT_FOUND alias maps to KEY_VALID', () => {
    mockValidateArtifact.mockReturnValue(blockResult('PUBLIC_KEY_NOT_FOUND'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.failedCheck).toBe('KEY_VALID');
  });

  test('VP-23 TIMESTAMP_IN_FUTURE alias maps to TIMESTAMP', () => {
    mockValidateArtifact.mockReturnValue(blockResult('TIMESTAMP_IN_FUTURE'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.failedCheck).toBe('TIMESTAMP');
  });

  test('VP-24 failure reason carries through from details.issue', () => {
    mockValidateArtifact.mockReturnValue(
      blockResult('INVALID_ARTIFACT', { issue: 'payload must be a plain object' })
    );
    const result = portal.runPortalChecks(makeArtifact());
    const schemaCheck = result.checks.find(c => c.check === 'SCHEMA');
    expect(schemaCheck.reason).toBe('payload must be a plain object');
  });

  test('VP-25 failure reason falls back to block reason when no details.issue', () => {
    mockValidateArtifact.mockReturnValue(blockResult('INVALID_SIGNATURE'));
    const result = portal.runPortalChecks(makeArtifact());
    const sigCheck = result.checks.find(c => c.check === 'SIGNATURE');
    expect(sigCheck.reason).toBe('INVALID_SIGNATURE');
  });

  test('VP-26 check array always starts with SCHEMA', () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    expect(result.checks[0].check).toBe('SCHEMA');
  });

  test('VP-27 total checks emitted: 8 (6 core + REPLAY_CHECK + EVIDENCE_CHAIN)', () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    expect(result.checks).toHaveLength(8);
  });

  test('VP-28 total checks emitted on failure: 8 (6 core + 2 advisory SKIPs)', () => {
    mockValidateArtifact.mockReturnValue(blockResult('EXPIRED'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.checks).toHaveLength(8);
  });

  test('VP-29 valid is false on BLOCK', () => {
    mockValidateArtifact.mockReturnValue(blockResult('INVALID_ARTIFACT'));
    const result = portal.runPortalChecks(makeArtifact());
    expect(result.valid).toBe(false);
  });

  test('VP-30 _clock option is forwarded to validateArtifact', () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const _clock = () => 999_999_999_999;
    portal.runPortalChecks(makeArtifact(), { _clock });
    expect(mockValidateArtifact).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ _clock }),
    );
  });
});

// ── VP-31 … VP-50: runPortalChecks — advisory checks and passing scenarios ────

describe('VP-31 … VP-50: runPortalChecks — advisory checks and passing scenarios', () => {
  beforeEach(() => {
    mockValidateArtifact.mockReset();
    mockValidateArtifact.mockReturnValue(EXECUTE);
  });

  test('VP-31 all core checks PASS when validateArtifact returns EXECUTE', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    const coreChecks = result.checks.filter(c =>
      ['SCHEMA', 'KEY_VALID', 'TIMESTAMP', 'NOT_EXPIRED', 'SIGNATURE', 'CLOCK_SKEW'].includes(c.check)
    );
    for (const c of coreChecks) {
      expect(c.result).toBe('PASS');
    }
  });

  test('VP-32 valid is true on EXECUTE', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    expect(result.valid).toBe(true);
  });

  test('VP-33 failedCheck is null on EXECUTE', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    expect(result.failedCheck).toBeNull();
  });

  test('VP-34 REPLAY_CHECK PASS when fingerprintSeen is false', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      fingerprintSeen: false,
      pgEnabled: false,
    });
    const replayCheck = result.checks.find(c => c.check === 'REPLAY_CHECK');
    expect(replayCheck.result).toBe('PASS');
  });

  test('VP-35 REPLAY_CHECK WARN when fingerprintSeen is true', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      fingerprintSeen: true,
      pgEnabled: false,
    });
    const replayCheck = result.checks.find(c => c.check === 'REPLAY_CHECK');
    expect(replayCheck.result).toBe('WARN');
    expect(replayCheck.reason).toContain('previously submitted');
  });

  test('VP-36 EVIDENCE_CHAIN SKIP when pgEnabled is false', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    const evCheck = result.checks.find(c => c.check === 'EVIDENCE_CHAIN');
    expect(evCheck.result).toBe('SKIP');
    expect(evCheck.reason).toContain('PostgreSQL not configured');
  });

  test('VP-37 EVIDENCE_CHAIN PASS when pgEnabled and evidenceRecord found', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      pgEnabled:      true,
      evidenceRecord: { evidence_id: 'abc', artifact_id: 'art-001' },
    });
    const evCheck = result.checks.find(c => c.check === 'EVIDENCE_CHAIN');
    expect(evCheck.result).toBe('PASS');
  });

  test('VP-38 EVIDENCE_CHAIN WARN when pgEnabled and no evidenceRecord', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      pgEnabled:      true,
      evidenceRecord: null,
    });
    const evCheck = result.checks.find(c => c.check === 'EVIDENCE_CHAIN');
    expect(evCheck.result).toBe('WARN');
    expect(evCheck.reason).toContain('not found in the QODIQA evidence chain');
  });

  test('VP-39 hasWarnings is true when REPLAY_CHECK is WARN', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      fingerprintSeen: true,
      pgEnabled:       false,
    });
    expect(result.hasWarnings).toBe(true);
  });

  test('VP-40 hasWarnings is true when EVIDENCE_CHAIN is WARN', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      pgEnabled:      true,
      evidenceRecord: null,
    });
    expect(result.hasWarnings).toBe(true);
  });

  test('VP-41 hasWarnings is false when all advisory checks PASS', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      fingerprintSeen: false,
      pgEnabled:       true,
      evidenceRecord:  { evidence_id: 'x' },
    });
    expect(result.hasWarnings).toBe(false);
  });

  test('VP-42 both REPLAY_CHECK and EVIDENCE_CHAIN can warn simultaneously', () => {
    const result = portal.runPortalChecks(makeArtifact(), {
      fingerprintSeen: true,
      pgEnabled:       true,
      evidenceRecord:  null,
    });
    const warns = result.checks.filter(c => c.result === 'WARN');
    expect(warns.map(c => c.check)).toContain('REPLAY_CHECK');
    expect(warns.map(c => c.check)).toContain('EVIDENCE_CHAIN');
  });

  test('VP-43 check order is deterministic: SCHEMA is first', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    expect(result.checks[0].check).toBe('SCHEMA');
  });

  test('VP-44 REPLAY_CHECK appears after CLOCK_SKEW in the list', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    const clockIdx  = result.checks.findIndex(c => c.check === 'CLOCK_SKEW');
    const replayIdx = result.checks.findIndex(c => c.check === 'REPLAY_CHECK');
    expect(replayIdx).toBeGreaterThan(clockIdx);
  });

  test('VP-45 EVIDENCE_CHAIN is always the last check', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    expect(result.checks[result.checks.length - 1].check).toBe('EVIDENCE_CHAIN');
  });

  test('VP-46 fingerprintSeen defaults to false when omitted', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    const replayCheck = result.checks.find(c => c.check === 'REPLAY_CHECK');
    expect(replayCheck.result).toBe('PASS');
  });

  test('VP-47 pgEnabled defaults to false when omitted', () => {
    const result = portal.runPortalChecks(makeArtifact());
    const evCheck = result.checks.find(c => c.check === 'EVIDENCE_CHAIN');
    expect(evCheck.result).toBe('SKIP');
  });

  test('VP-48 EXECUTE with SKIP advisory (pgDisabled) has hasWarnings false', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    expect(result.hasWarnings).toBe(false);
  });

  test('VP-49 result.checks contains only recognized check names', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: true, evidenceRecord: null });
    const valid = new Set([
      'SCHEMA', 'KEY_VALID', 'TIMESTAMP', 'NOT_EXPIRED',
      'SIGNATURE', 'CLOCK_SKEW', 'REPLAY_CHECK', 'EVIDENCE_CHAIN',
    ]);
    for (const c of result.checks) {
      expect(valid.has(c.check)).toBe(true);
    }
  });

  test('VP-50 each check entry has check, result, and optional reason fields only', () => {
    const result = portal.runPortalChecks(makeArtifact(), { pgEnabled: false });
    for (const c of result.checks) {
      expect(typeof c.check).toBe('string');
      expect(['PASS', 'FAIL', 'SKIP', 'WARN']).toContain(c.result);
    }
  });
});

// ── VP-51 … VP-65: buildVerificationReport ────────────────────────────────────

describe('VP-51 … VP-65: buildVerificationReport (portal.js)', () => {
  function passChecks() {
    return [
      { check: 'SCHEMA',         result: 'PASS' },
      { check: 'KEY_VALID',      result: 'PASS' },
      { check: 'TIMESTAMP',      result: 'PASS' },
      { check: 'NOT_EXPIRED',    result: 'PASS' },
      { check: 'SIGNATURE',      result: 'PASS' },
      { check: 'CLOCK_SKEW',     result: 'PASS' },
      { check: 'REPLAY_CHECK',   result: 'PASS' },
      { check: 'EVIDENCE_CHAIN', result: 'PASS' },
    ];
  }

  function withFail(check, reason = 'reason') {
    return passChecks().map(c => c.check === check ? { ...c, result: 'FAIL', reason } : c);
  }

  function withWarn(check, reason = 'warning reason') {
    return passChecks().map(c => c.check === check ? { ...c, result: 'WARN', reason } : c);
  }

  test('VP-51 all PASS → overallResult VERIFIED', () => {
    const report = portal.buildVerificationReport(passChecks());
    expect(report.overallResult).toBe('VERIFIED');
  });

  test('VP-52 any FAIL → overallResult FAILED', () => {
    const report = portal.buildVerificationReport(withFail('SIGNATURE'));
    expect(report.overallResult).toBe('FAILED');
  });

  test('VP-53 WARN (no FAIL) → overallResult VERIFIED_WITH_WARNINGS', () => {
    const report = portal.buildVerificationReport(withWarn('REPLAY_CHECK'));
    expect(report.overallResult).toBe('VERIFIED_WITH_WARNINGS');
  });

  test('VP-54 failedCheck is the name of the failing check', () => {
    const report = portal.buildVerificationReport(withFail('NOT_EXPIRED', 'expired'));
    expect(report.failedCheck).toBe('NOT_EXPIRED');
  });

  test('VP-55 failureReason is the reason from the failing check', () => {
    const report = portal.buildVerificationReport(withFail('SIGNATURE', 'sig bad'));
    expect(report.failureReason).toBe('sig bad');
  });

  test('VP-56 failedCheck is null when no failures', () => {
    const report = portal.buildVerificationReport(passChecks());
    expect(report.failedCheck).toBeNull();
  });

  test('VP-57 failureReason is null when no failures', () => {
    const report = portal.buildVerificationReport(passChecks());
    expect(report.failureReason).toBeNull();
  });

  test('VP-58 warnings array contains all WARN checks', () => {
    const checks = [
      ...passChecks().slice(0, 6),
      { check: 'REPLAY_CHECK',   result: 'WARN', reason: 'seen before' },
      { check: 'EVIDENCE_CHAIN', result: 'WARN', reason: 'not in chain' },
    ];
    const report = portal.buildVerificationReport(checks);
    expect(report.warnings).toHaveLength(2);
    expect(report.warnings.map(w => w.check)).toContain('REPLAY_CHECK');
    expect(report.warnings.map(w => w.check)).toContain('EVIDENCE_CHAIN');
  });

  test('VP-59 warnings array is empty when no WARNs', () => {
    const report = portal.buildVerificationReport(passChecks());
    expect(report.warnings).toHaveLength(0);
  });

  test('VP-60 FAIL takes precedence over WARN: still FAILED', () => {
    const checks = withFail('SCHEMA');
    checks.push({ check: 'REPLAY_CHECK', result: 'WARN', reason: 'warn' });
    const report = portal.buildVerificationReport(checks);
    expect(report.overallResult).toBe('FAILED');
  });

  test('VP-61 metadata fields are set from meta argument', () => {
    const meta = { publicKeyId: 'k1', timestampMs: 1000, expiryMs: 2000, artifactId: 'art-1' };
    const report = portal.buildVerificationReport(passChecks(), meta);
    expect(report.metadata.publicKeyId).toBe('k1');
    expect(report.metadata.timestampMs).toBe(1000);
    expect(report.metadata.expiryMs).toBe(2000);
    expect(report.metadata.artifactId).toBe('art-1');
  });

  test('VP-62 metadata defaults to null when meta not provided', () => {
    const report = portal.buildVerificationReport(passChecks());
    expect(report.metadata.publicKeyId).toBeNull();
    expect(report.metadata.timestampMs).toBeNull();
    expect(report.metadata.expiryMs).toBeNull();
    expect(report.metadata.artifactId).toBeNull();
  });

  test('VP-63 report includes the checks array', () => {
    const checks = passChecks();
    const report = portal.buildVerificationReport(checks);
    expect(report.checks).toBe(checks);
  });

  test('VP-64 first failure in check order is used as failedCheck', () => {
    const checks = passChecks().map(c => {
      if (c.check === 'SCHEMA') return { ...c, result: 'FAIL', reason: 'schema fail' };
      if (c.check === 'SIGNATURE') return { ...c, result: 'FAIL', reason: 'sig fail' };
      return c;
    });
    const report = portal.buildVerificationReport(checks);
    expect(report.failedCheck).toBe('SCHEMA');
    expect(report.failureReason).toBe('schema fail');
  });

  test('VP-65 SKIP checks do not contribute to WARN or FAIL results', () => {
    const checks = passChecks().map(c =>
      c.check === 'EVIDENCE_CHAIN' ? { ...c, result: 'SKIP', reason: 'PG disabled' } : c
    );
    const report = portal.buildVerificationReport(checks);
    expect(report.overallResult).toBe('VERIFIED');
    expect(report.warnings).toHaveLength(0);
  });
});

// ── VP-66 … VP-80: portalStore — PG-disabled path ────────────────────────────

describe('VP-66 … VP-80: portalStore — PG-disabled path (portalStore.js)', () => {
  beforeEach(() => {
    mockPool._enabled = false;
    mockPool.query.mockReset();
  });

  test('VP-66 recordVerification returns null when PG disabled', async () => {
    const result = await portalStore.recordVerification({
      verificationId:      randomUUID(),
      artifactFingerprint: 'a'.repeat(64),
      overallResult:       'VERIFIED',
      checksPerformed:     [],
    });
    expect(result).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('VP-67 getByVerificationId returns null when PG disabled', async () => {
    const result = await portalStore.getByVerificationId(randomUUID());
    expect(result).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('VP-68 getByFingerprint returns null when PG disabled', async () => {
    const result = await portalStore.getByFingerprint('a'.repeat(64));
    expect(result).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('VP-69 listVerifications returns empty result when PG disabled', async () => {
    const result = await portalStore.listVerifications();
    expect(result.verifications).toHaveLength(0);
    expect(result.total).toBe(0);
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('VP-70 listVerifications preserves page and pageSize in response', async () => {
    const result = await portalStore.listVerifications({ page: 3, pageSize: 25 });
    expect(result.page).toBe(3);
    expect(result.pageSize).toBe(25);
  });

  test('VP-71 aggregateStats returns null when PG disabled', async () => {
    const result = await portalStore.aggregateStats();
    expect(result).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });
});

// ── VP-81 … VP-100: portalStore — PG-enabled path ────────────────────────────

describe('VP-81 … VP-100: portalStore — PG-enabled path (portalStore.js)', () => {
  beforeEach(() => {
    mockPool._enabled = true;
    mockPool.query.mockReset();
  });

  const sampleRow = {
    id:                    1,
    verification_id:       randomUUID(),
    artifact_fingerprint:  'b'.repeat(64),
    artifact_public_key_id: 'default:key_v1',
    artifact_timestamp_ms: 1700000000000,
    artifact_expiry_ms:    1700003600000,
    artifact_id:           'art-001',
    overall_result:        'VERIFIED',
    checks_performed:      [],
    failed_check:          null,
    failure_reason:        null,
    warnings:              [],
    transparency_id:       null,
    submitted_by:          'public',
    submission_ip:         '127.0.0.1',
    duration_ms:           42,
    verified_at:           new Date().toISOString(),
  };

  test('VP-81 recordVerification issues INSERT with correct params', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });

    const vId = randomUUID();
    await portalStore.recordVerification({
      verificationId:      vId,
      artifactFingerprint: 'b'.repeat(64),
      overallResult:       'VERIFIED',
      checksPerformed:     [],
    });

    expect(mockPool.query).toHaveBeenCalledTimes(1);
    const [sql, params] = mockPool.query.mock.calls[0];
    expect(sql).toContain('INSERT INTO portal_verifications');
    expect(params[0]).toBe(vId);
  });

  test('VP-82 recordVerification returns the inserted row', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });

    const result = await portalStore.recordVerification({
      verificationId:      randomUUID(),
      artifactFingerprint: 'b'.repeat(64),
      overallResult:       'VERIFIED',
      checksPerformed:     [],
    });
    expect(result).toBe(sampleRow);
  });

  test('VP-83 recordVerification returns null when INSERT returns no rows', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });

    const result = await portalStore.recordVerification({
      verificationId:      randomUUID(),
      artifactFingerprint: 'b'.repeat(64),
      overallResult:       'FAILED',
      checksPerformed:     [],
    });
    expect(result).toBeNull();
  });

  test('VP-84 getByVerificationId queries by verification_id', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });

    const vId = randomUUID();
    const result = await portalStore.getByVerificationId(vId);

    const [sql, params] = mockPool.query.mock.calls[0];
    expect(sql).toContain('WHERE verification_id');
    expect(params[0]).toBe(vId);
    expect(result).toBe(sampleRow);
  });

  test('VP-85 getByVerificationId returns null when no row found', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });

    const result = await portalStore.getByVerificationId(randomUUID());
    expect(result).toBeNull();
  });

  test('VP-86 getByFingerprint queries by artifact_fingerprint', async () => {
    const fp = 'c'.repeat(64);
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });

    const result = await portalStore.getByFingerprint(fp);

    const [sql, params] = mockPool.query.mock.calls[0];
    expect(sql).toContain('artifact_fingerprint');
    expect(params[0]).toBe(fp);
    expect(result).toBe(sampleRow);
  });

  test('VP-87 getByFingerprint returns null when not found', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });

    const result = await portalStore.getByFingerprint('d'.repeat(64));
    expect(result).toBeNull();
  });

  test('VP-88 listVerifications runs two queries (data + count)', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [sampleRow] })
      .mockResolvedValueOnce({ rows: [{ total: '1' }] });

    const result = await portalStore.listVerifications();

    expect(mockPool.query).toHaveBeenCalledTimes(2);
    expect(result.verifications).toHaveLength(1);
    expect(result.total).toBe(1);
  });

  test('VP-89 listVerifications passes overallResult filter', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    await portalStore.listVerifications({ overallResult: 'FAILED' });

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('overall_result');
  });

  test('VP-90 listVerifications caps pageSize at 500', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    const result = await portalStore.listVerifications({ pageSize: 9999 });
    expect(result.pageSize).toBe(500);
  });

  test('VP-91 listVerifications uses DESC sort by default', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    await portalStore.listVerifications();

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('DESC');
  });

  test('VP-92 listVerifications uses ASC sort when requested', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    await portalStore.listVerifications({ sortOrder: 'asc' });

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('ASC');
  });

  test('VP-93 aggregateStats queries portal_verifications', async () => {
    const statsRow = {
      total: '100', verified_count: '80', warnings_count: '10', failed_count: '10',
      schema_failures: '2', signature_failures: '5', expiry_failures: '1',
      timestamp_failures: '0', clock_skew_failures: '2', key_failures: '0',
      first_verification: null, last_verification: null, table_size: '16 kB',
    };
    mockPool.query.mockResolvedValue({ rows: [statsRow] });

    const result = await portalStore.aggregateStats();

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('portal_verifications');
    expect(result.total).toBe(100);
    expect(result.verifiedCount).toBe(80);
    expect(result.failedCount).toBe(10);
    expect(result.tableSize).toBe('16 kB');
  });

  test('VP-94 aggregateStats returns zero-values when no rows', async () => {
    mockPool.query.mockResolvedValue({ rows: [{}] });

    const result = await portalStore.aggregateStats();
    expect(result.total).toBe(0);
    expect(result.verifiedCount).toBe(0);
  });

  test('VP-95 recordVerification passes RETURNING clause', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });

    await portalStore.recordVerification({
      verificationId:      randomUUID(),
      artifactFingerprint: 'e'.repeat(64),
      overallResult:       'VERIFIED_WITH_WARNINGS',
      checksPerformed:     [],
    });

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('RETURNING');
  });

  test('VP-96 recordVerification serializes checksPerformed as JSON string', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });

    const checks = [{ check: 'SCHEMA', result: 'PASS' }];
    await portalStore.recordVerification({
      verificationId:      randomUUID(),
      artifactFingerprint: 'f'.repeat(64),
      overallResult:       'VERIFIED',
      checksPerformed:     checks,
    });

    const [, params] = mockPool.query.mock.calls[0];
    const checksParam = params.find(p => typeof p === 'string' && p.includes('SCHEMA'));
    expect(checksParam).toBe(JSON.stringify(checks));
  });

  test('VP-97 listVerifications filters by failedCheck', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    await portalStore.listVerifications({ failedCheck: 'SIGNATURE' });

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('failed_check');
  });

  test('VP-98 listVerifications filters by artifactId', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    await portalStore.listVerifications({ artifactId: 'art-001' });

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('artifact_id');
  });

  test('VP-99 listVerifications respects startTime and endTime filters', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    await portalStore.listVerifications({
      startTime: '2024-01-01T00:00:00Z',
      endTime:   '2024-12-31T23:59:59Z',
    });

    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('verified_at');
  });

  test('VP-100 listVerifications page 2 with pageSize 10 produces correct offset', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });

    await portalStore.listVerifications({ page: 2, pageSize: 10 });

    const [, params] = mockPool.query.mock.calls[0];
    // OFFSET should be (2-1) * 10 = 10
    expect(params).toContain(10);  // pageSize
    expect(params).toContain(10);  // offset
  });
});

// ── VP-101 … VP-110: RBAC permissions matrix ──────────────────────────────────

describe('VP-101 … VP-110: RBAC permissions matrix', () => {
  test('VP-101 READ_VERIFICATION_PORTAL is defined in PERMISSIONS', () => {
    expect(PERMISSIONS.READ_VERIFICATION_PORTAL).toBeDefined();
  });

  test('VP-102 MANAGE_VERIFICATION_PORTAL is defined in PERMISSIONS', () => {
    expect(PERMISSIONS.MANAGE_VERIFICATION_PORTAL).toBeDefined();
  });

  test('VP-103 admin can READ_VERIFICATION_PORTAL', () => {
    expect(PERMISSIONS.READ_VERIFICATION_PORTAL).toContain('admin');
  });

  test('VP-104 auditor can READ_VERIFICATION_PORTAL', () => {
    expect(PERMISSIONS.READ_VERIFICATION_PORTAL).toContain('auditor');
  });

  test('VP-105 compliance can READ_VERIFICATION_PORTAL', () => {
    expect(PERMISSIONS.READ_VERIFICATION_PORTAL).toContain('compliance');
  });

  test('VP-106 operator cannot READ_VERIFICATION_PORTAL', () => {
    expect(PERMISSIONS.READ_VERIFICATION_PORTAL).not.toContain('operator');
  });

  test('VP-107 viewer cannot READ_VERIFICATION_PORTAL', () => {
    expect(PERMISSIONS.READ_VERIFICATION_PORTAL).not.toContain('viewer');
  });

  test('VP-108 only admin can MANAGE_VERIFICATION_PORTAL', () => {
    expect(PERMISSIONS.MANAGE_VERIFICATION_PORTAL).toEqual(
      expect.arrayContaining(['admin'])
    );
    expect(PERMISSIONS.MANAGE_VERIFICATION_PORTAL).not.toContain('auditor');
    expect(PERMISSIONS.MANAGE_VERIFICATION_PORTAL).not.toContain('compliance');
    expect(PERMISSIONS.MANAGE_VERIFICATION_PORTAL).not.toContain('operator');
    expect(PERMISSIONS.MANAGE_VERIFICATION_PORTAL).not.toContain('viewer');
  });

  test('VP-109 _REASON_TO_FAILED_CHECK covers all validateArtifact block reasons', () => {
    const map = portal._REASON_TO_FAILED_CHECK;
    expect(map.INVALID_ARTIFACT).toBe('SCHEMA');
    expect(map.KEY_NOT_FOUND).toBe('KEY_VALID');
    expect(map.FUTURE_TIMESTAMP).toBe('TIMESTAMP');
    expect(map.EXPIRED).toBe('NOT_EXPIRED');
    expect(map.INVALID_SIGNATURE).toBe('SIGNATURE');
    expect(map.CLOCK_SKEW_EXCEEDED).toBe('CLOCK_SKEW');
  });

  test('VP-110 _CHECK_ORDER has exactly 6 elements covering the full crypto suite', () => {
    expect(portal._CHECK_ORDER).toHaveLength(6);
    expect(portal._CHECK_ORDER[0]).toBe('SCHEMA');
    expect(portal._CHECK_ORDER[portal._CHECK_ORDER.length - 1]).toBe('CLOCK_SKEW');
  });
});

// ── VP-111 … VP-120: assemblePortalEvidencePackage ────────────────────────────

describe('VP-111 … VP-120: assemblePortalEvidencePackage (portal.js)', () => {
  const sampleRecord = {
    verification_id:        '11111111-1111-1111-1111-111111111111',
    artifact_fingerprint:   'a'.repeat(64),
    artifact_public_key_id: 'default:key_v1',
    artifact_timestamp_ms:  1700000000000,
    artifact_expiry_ms:     1700003600000,
    artifact_id:            'art-111',
    overall_result:         'VERIFIED',
    checks_performed:       [{ check: 'SCHEMA', result: 'PASS' }],
    failed_check:           null,
    failure_reason:         null,
    warnings:               [],
    transparency_id:        '22222222-2222-2222-2222-222222222222',
    submitted_by:           'public',
    submission_ip:          '127.0.0.1',
    duration_ms:            42,
    verified_at:            '2026-01-01T00:00:00.000Z',
  };

  test('VP-111 returns an object with packageType QODIQA::PORTAL_EVIDENCE::V1', () => {
    const pkg = portal.assemblePortalEvidencePackage(sampleRecord);
    expect(pkg.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
  });

  test('VP-112 verificationId is populated from verification_id', () => {
    const pkg = portal.assemblePortalEvidencePackage(sampleRecord);
    expect(pkg.verificationId).toBe(sampleRecord.verification_id);
  });

  test('VP-113 overallResult matches the stored record', () => {
    const pkg = portal.assemblePortalEvidencePackage(sampleRecord);
    expect(pkg.overallResult).toBe('VERIFIED');
  });

  test('VP-114 transparencyId is carried through from the record', () => {
    const pkg = portal.assemblePortalEvidencePackage(sampleRecord);
    expect(pkg.transparencyId).toBe(sampleRecord.transparency_id);
  });

  test('VP-115 packageHash is a 64-char hex SHA-256 string', () => {
    const pkg = portal.assemblePortalEvidencePackage(sampleRecord);
    expect(pkg.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('VP-116 packageId is a 64-char hex SHA-256 string', () => {
    const pkg = portal.assemblePortalEvidencePackage(sampleRecord);
    expect(pkg.packageId).toMatch(/^[0-9a-f]{64}$/);
  });

  test('VP-117 generatedAt is an ISO 8601 date string', () => {
    const pkg = portal.assemblePortalEvidencePackage(sampleRecord);
    expect(() => new Date(pkg.generatedAt)).not.toThrow();
    expect(pkg.generatedAt).toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  test('VP-118 packageHash changes when overallResult changes', () => {
    const pkg1 = portal.assemblePortalEvidencePackage(sampleRecord);
    const pkg2 = portal.assemblePortalEvidencePackage({ ...sampleRecord, overall_result: 'FAILED' });
    expect(pkg1.packageHash).not.toBe(pkg2.packageHash);
  });

  test('VP-119 accepts camelCase field names (in-memory record format)', () => {
    const camelRecord = {
      verificationId:      sampleRecord.verification_id,
      artifactFingerprint: sampleRecord.artifact_fingerprint,
      overallResult:       sampleRecord.overall_result,
      checksPerformed:     sampleRecord.checks_performed,
      warnings:            sampleRecord.warnings,
    };
    const pkg = portal.assemblePortalEvidencePackage(camelRecord);
    expect(pkg.verificationId).toBe(sampleRecord.verification_id);
    expect(pkg.overallResult).toBe('VERIFIED');
  });

  test('VP-120 throws TypeError when record is null or non-object', () => {
    expect(() => portal.assemblePortalEvidencePackage(null)).toThrow(TypeError);
    expect(() => portal.assemblePortalEvidencePackage('string')).toThrow(TypeError);
    expect(() => portal.assemblePortalEvidencePackage(42)).toThrow(TypeError);
  });
});

// ── evidence-chain correlation key ──────────────────────────────────────
// The artifact identifier is its signed payload.requestId (QODIQA-PROTOCOL-SPEC
// §10.11/§12.1), the key audit_chain and evidence_chain_records are written
// under. payload.artifactId is caller-chosen (an open /sign payload field) and
// must never select an evidence record: keying on it hid genuine executions and
// let an unexecuted artifact claim another execution's evidence (reproduced
// live against a real server).
describe('VP-121 … VP-128: evidenceArtifactId / lookupEvidenceRecord', () => {
  const store = (rec) => ({ getByArtifactId: jest.fn(async () => rec) });

  test('VP-121 evidenceArtifactId is payload.requestId', () => {
    expect(portal.evidenceArtifactId({ payload: { requestId: 'r-1', artifactId: 'other' } })).toBe('r-1');
  });

  test('VP-122 evidenceArtifactId ignores payload.artifactId when requestId is absent', () => {
    expect(portal.evidenceArtifactId({ payload: { artifactId: 'claimed' } })).toBeNull();
  });

  test('VP-123 evidenceArtifactId is null for a missing/empty/non-string requestId', () => {
    expect(portal.evidenceArtifactId(null)).toBeNull();
    expect(portal.evidenceArtifactId({ payload: {} })).toBeNull();
    expect(portal.evidenceArtifactId({ payload: { requestId: '' } })).toBeNull();
    expect(portal.evidenceArtifactId({ payload: { requestId: 42 } })).toBeNull();
  });

  test('VP-124 lookupEvidenceRecord queries by payload.requestId, never payload.artifactId', async () => {
    const cs = store({ artifact_id: 'r-1', tenant_id: 't-a' });
    const rec = await portal.lookupEvidenceRecord({ payload: { requestId: 'r-1', artifactId: 'victim', tenantId: 't-a' } }, cs);
    expect(cs.getByArtifactId).toHaveBeenCalledTimes(1);
    expect(cs.getByArtifactId).toHaveBeenCalledWith('r-1');
    expect(rec).toEqual({ artifact_id: 'r-1', tenant_id: 't-a' });
  });

  test('VP-125 no identifier -> no query, null', async () => {
    const cs = store({ artifact_id: 'x' });
    expect(await portal.lookupEvidenceRecord({ payload: { artifactId: 'victim' } }, cs)).toBeNull();
    expect(cs.getByArtifactId).not.toHaveBeenCalled();
  });

  test('VP-126 unknown identifier -> null', async () => {
    expect(await portal.lookupEvidenceRecord({ payload: { requestId: 'r-unknown', tenantId: 't-a' } }, store(null))).toBeNull();
  });

  test('VP-127 a record from a different tenant is treated as absent (fail closed)', async () => {
    const cs = store({ artifact_id: 'r-1', tenant_id: 't-b' });
    expect(await portal.lookupEvidenceRecord({ payload: { requestId: 'r-1', tenantId: 't-a' } }, cs)).toBeNull();
    expect(await portal.lookupEvidenceRecord({ payload: { requestId: 'r-1' } }, cs)).toBeNull();
  });

  test('VP-128 a record with no tenant (platform-level) is accepted for the matching requestId', async () => {
    const rec = { artifact_id: 'r-1', tenant_id: null };
    expect(await portal.lookupEvidenceRecord({ payload: { requestId: 'r-1', tenantId: 't-a' } }, store(rec))).toBe(rec);
  });
});

// the submitter address is internal
// audit data. It is withheld from public responses, but the V1 evidence-package
// hash contract is deliberately UNCHANGED — the address stays in the canonical
// content, so previously issued V1 packages keep verifying. Golden value
// computed on the pre-H130 tree (39e3bcd5); it must never move.
describe('H130-VP-01 … H130-VP-02: V1 evidence-package hash contract unchanged', () => {
  const H130_RECORD = {
    verification_id: '5b1f0c7e-1f2a-4c3b-9d4e-0a1b2c3d4e5f', artifact_fingerprint: 'b'.repeat(64),
    artifact_public_key_id: 'default:key_v1', artifact_timestamp_ms: 1700000000000, artifact_expiry_ms: 1700003600000,
    artifact_id: 'art-h130', overall_result: 'VERIFIED', checks_performed: [{ check: 'SCHEMA', result: 'PASS' }],
    failed_check: null, failure_reason: null, warnings: [], transparency_id: 'trans-h130', submitted_by: 'public',
    submission_ip: '203.0.113.10', duration_ms: 42, verified_at: new Date('2026-09-25T00:00:00.000Z'),
  };

  test('H130-VP-01 the V1 package for a fixed record still hashes to the pre-H130 golden value', () => {
    const pkg = portal.assembleEvidencePackageFromPortalRecord(H130_RECORD);
    expect(pkg.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
    expect(pkg.packageHash).toBe('c020aa8854dcf89eb0dac8921bfdad8fbbdaca193f74ba5f0f58134dd13d4cc9');
  });

  test('H130-VP-02 submissionIp remains part of the V1 canonical content (internal audit field)', () => {
    const pkg = portal.assembleEvidencePackageFromPortalRecord(H130_RECORD);
    expect(pkg.submissionIp).toBe('203.0.113.10');
    expect(portal.assembleEvidencePackageFromPortalRecord({ ...H130_RECORD, submission_ip: null }).packageHash)
      .not.toBe(pkg.packageHash);
  });
});
