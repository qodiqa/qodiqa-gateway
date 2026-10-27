'use strict';

/**
 * Global execution invariant guard tests.
 *
 * Verifies:
 *   - Every valid, cryptographically-bound context passes
 *   - Every invalid context is rejected with UNVERIFIED_EXECUTION_ATTEMPT
 *   - Violations are logged to stderr before the throw
 *   - Stats counters track totalAttempts = verifiedCalls + violationCount
 *   - executeProviderCall enforces the invariant before any provider I/O
 * - a forged-but-correctly-shaped verifiedCtx is cryptographically
 *     rejected — shape alone is never sufficient (see "HMAC binding" below)
 */

const crypto = require('crypto');
const { assertExecutionInvariant, getStats, resetStats } = require('../execution-guard');
const { mintExecutionToken } = require('../executionInvariantToken');

const VALID_HASH        = 'a'.repeat(64);
const VALID_POLICY_HASH = 'b'.repeat(64);

function buildValidCtx(overrides = {}) {
  const requestHash = overrides.requestHash ?? VALID_HASH;
  const policyHash  = overrides.policyHash  ?? VALID_POLICY_HASH;
  const { issuedAt, signature } = mintExecutionToken({ requestHash, policyHash });
  return Object.freeze({
    verified:    true,
    requestHash,
    policyHash,
    artifactId:  'test-id',
    tenantId:    'test-tenant',
    issuedAt,
    signature,
    ...overrides,
  });
}

const VALID_CTX = buildValidCtx();

beforeEach(() => {
  resetStats();
});

// ── Invariant: valid context ──────────────────────────────────────────────────

describe('assertExecutionInvariant — valid context', () => {
  test('does not throw for a fully valid, correctly-signed context', () => {
    expect(() => assertExecutionInvariant(buildValidCtx())).not.toThrow();
  });

  test('increments verifiedCalls on success', () => {
    assertExecutionInvariant(buildValidCtx());
    expect(getStats().verifiedCalls).toBe(1);
    expect(getStats().violationCount).toBe(0);
  });

  test('totalAttempts = verifiedCalls + violationCount after mixed calls', () => {
    assertExecutionInvariant(buildValidCtx());
    try { assertExecutionInvariant(null); } catch {}
    try { assertExecutionInvariant(undefined); } catch {}
    assertExecutionInvariant(buildValidCtx());

    const { totalAttempts, verifiedCalls, violationCount } = getStats();
    expect(totalAttempts).toBe(4);
    expect(verifiedCalls).toBe(2);
    expect(violationCount).toBe(2);
    expect(totalAttempts).toBe(verifiedCalls + violationCount);
  });
});

// ── Invariant: missing / null / wrong type ────────────────────────────────────

describe('assertExecutionInvariant — missing context', () => {
  const cases = [
    ['undefined', undefined],
    ['null',      null],
    ['number',    42],
    ['string',    'verified'],
    ['array',     [{ verified: true }]],
    ['boolean',   true],
  ];

  test.each(cases)('%s → throws UNVERIFIED_EXECUTION_ATTEMPT', (_label, ctx) => {
    expect(() => assertExecutionInvariant(ctx)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test.each(cases)('%s → increments violationCount', (_label, ctx) => {
    try { assertExecutionInvariant(ctx); } catch {}
    expect(getStats().violationCount).toBe(1);
    expect(getStats().verifiedCalls).toBe(0);
  });
});

// ── Invariant: verified flag ──────────────────────────────────────────────────

describe('assertExecutionInvariant — verified flag', () => {
  test('verified: false → throws', () => {
    expect(() => assertExecutionInvariant(buildValidCtx({ verified: false })))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('verified: 1 (truthy but not true) → throws', () => {
    expect(() => assertExecutionInvariant(buildValidCtx({ verified: 1 })))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('verified: "true" (string) → throws', () => {
    expect(() => assertExecutionInvariant(buildValidCtx({ verified: 'true' })))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('verified absent → throws', () => {
    const ctx = buildValidCtx();
    const { verified: _v, ...noVerified } = ctx;
    expect(() => assertExecutionInvariant(noVerified))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });
});

// ── Invariant: requestHash ────────────────────────────────────────────────────

describe('assertExecutionInvariant — requestHash', () => {
  test('missing requestHash → throws', () => {
    const ctx = buildValidCtx();
    const { requestHash: _rh, ...noHash } = ctx;
    expect(() => assertExecutionInvariant(noHash)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('requestHash too short (63 chars) → throws', () => {
    expect(() => assertExecutionInvariant({ ...buildValidCtx(), requestHash: 'a'.repeat(63) }))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('requestHash too long (65 chars) → throws', () => {
    expect(() => assertExecutionInvariant({ ...buildValidCtx(), requestHash: 'a'.repeat(65) }))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('requestHash with non-hex chars → throws', () => {
    expect(() => assertExecutionInvariant({ ...buildValidCtx(), requestHash: 'g'.repeat(64) }))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('requestHash uppercase hex → throws (must be lowercase)', () => {
    expect(() => assertExecutionInvariant({ ...buildValidCtx(), requestHash: 'A'.repeat(64) }))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('requestHash null → throws', () => {
    expect(() => assertExecutionInvariant({ ...buildValidCtx(), requestHash: null }))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });
});

// ── Invariant: artifactId ─────────────────────────────────────────────────────

describe('assertExecutionInvariant — artifactId', () => {
  test('missing artifactId → throws', () => {
    const ctx = buildValidCtx();
    const { artifactId: _a, ...noId } = ctx;
    expect(() => assertExecutionInvariant(noId)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('empty string artifactId → throws', () => {
    expect(() => assertExecutionInvariant(buildValidCtx({ artifactId: '' })))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('null artifactId → throws', () => {
    expect(() => assertExecutionInvariant(buildValidCtx({ artifactId: null })))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('numeric artifactId → throws', () => {
    expect(() => assertExecutionInvariant(buildValidCtx({ artifactId: 12345 })))
      .toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });
});

// ── cryptographic HMAC binding ────────────────────────────────────────
//
// Every case below starts from a genuinely pipeline-minted token
// (buildValidCtx / mintExecutionToken) and then corrupts exactly one field —
// proving the rejection is driven by the signature check, not by a
// structural/format check that happens to reject the same input.

describe('assertExecutionInvariant — cryptographic HMAC binding', () => {
  test('valid pipeline-issued context passes', () => {
    expect(() => assertExecutionInvariant(buildValidCtx())).not.toThrow();
  });

  test('forged context — correct shape, fabricated signature — is rejected', () => {
    const ctx = buildValidCtx();
    const forged = { ...ctx, signature: 'f'.repeat(64) };
    expect(() => assertExecutionInvariant(forged)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('modified requestHash (post-signing) is rejected — signature no longer matches', () => {
    const ctx = buildValidCtx();
    const tampered = { ...ctx, requestHash: 'c'.repeat(64) };
    expect(() => assertExecutionInvariant(tampered)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('modified policyHash (post-signing) is rejected — signature no longer matches', () => {
    const ctx = buildValidCtx();
    const tampered = { ...ctx, policyHash: 'd'.repeat(64) };
    expect(() => assertExecutionInvariant(tampered)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('modified issuedAt (post-signing) is rejected — signature no longer matches', () => {
    const ctx = buildValidCtx();
    const tampered = { ...ctx, issuedAt: ctx.issuedAt - 1 };
    expect(() => assertExecutionInvariant(tampered)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('missing signature is rejected', () => {
    const ctx = buildValidCtx();
    const { signature: _s, ...noSignature } = ctx;
    expect(() => assertExecutionInvariant(noSignature)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('corrupted signature (flipped hex digit) is rejected', () => {
    const ctx = buildValidCtx();
    const corruptedChar = ctx.signature[0] === '0' ? '1' : '0';
    const corrupted = { ...ctx, signature: corruptedChar + ctx.signature.slice(1) };
    expect(() => assertExecutionInvariant(corrupted)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('expired signature (issuedAt older than TTL) is rejected', () => {
    // A genuinely and correctly signed token for an issuedAt far enough in
    // the past that only the TTL check can reject it — proves expiry is
    // enforced independently of signature validity.
    const requestHash = VALID_HASH;
    const policyHash  = VALID_POLICY_HASH;
    const oldIssuedAt = Date.now() - 120_000; // 2 minutes ago — well past default 60s TTL
    const message     = `QODIQA::EXECUTION_INVARIANT::V1|${requestHash}|${policyHash}|${oldIssuedAt}`;
    const secret      = Buffer.from(process.env.QODIQA_EXECUTION_INVARIANT_SECRET, 'hex');
    const signature   = crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
    const expiredCtx  = { verified: true, requestHash, policyHash, artifactId: 'x', tenantId: 't', issuedAt: oldIssuedAt, signature };
    expect(() => assertExecutionInvariant(expiredCtx)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('random signature (no relationship to the secret) is rejected', () => {
    const ctx = buildValidCtx();
    const random = { ...ctx, signature: crypto.randomBytes(32).toString('hex') };
    expect(() => assertExecutionInvariant(random)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('correct shape but entirely unsigned (no issuedAt/signature fields at all) is rejected', () => {
    const unsigned = Object.freeze({
      verified: true, requestHash: VALID_HASH, policyHash: VALID_POLICY_HASH,
      artifactId: 'test-id', tenantId: 'test-tenant',
    });
    expect(() => assertExecutionInvariant(unsigned)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('signature produced with an incorrect HMAC secret is rejected', () => {
    const wrongSecret = crypto.randomBytes(32).toString('hex');
    const requestHash = VALID_HASH;
    const policyHash  = VALID_POLICY_HASH;
    const issuedAt    = Date.now();
    const message     = `QODIQA::EXECUTION_INVARIANT::V1|${requestHash}|${policyHash}|${issuedAt}`;
    const signature   = crypto.createHmac('sha256', Buffer.from(wrongSecret, 'hex')).update(message, 'utf8').digest('hex');
    const ctx = { verified: true, requestHash, policyHash, artifactId: 'x', tenantId: 't', issuedAt, signature };
    expect(() => assertExecutionInvariant(ctx)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('future timestamp (issuedAt ahead of server clock) is rejected', () => {
    const requestHash = VALID_HASH;
    const policyHash  = VALID_POLICY_HASH;
    const futureIssuedAt = Date.now() + 60_000; // 1 minute in the future
    const message     = `QODIQA::EXECUTION_INVARIANT::V1|${requestHash}|${policyHash}|${futureIssuedAt}`;
    const secret      = Buffer.from(process.env.QODIQA_EXECUTION_INVARIANT_SECRET, 'hex');
    const signature   = crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
    const ctx = { verified: true, requestHash, policyHash, artifactId: 'x', tenantId: 't', issuedAt: futureIssuedAt, signature };
    expect(() => assertExecutionInvariant(ctx)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('missing policyHash is rejected', () => {
    const ctx = buildValidCtx();
    const { policyHash: _p, ...noPolicyHash } = ctx;
    expect(() => assertExecutionInvariant(noPolicyHash)).toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('EXECUTION_TOKEN_INVALID violation code is reported for a forged signature', () => {
    const stderrWrite = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const ctx = buildValidCtx();
    const forged = { ...ctx, signature: 'f'.repeat(64) };
    try { assertExecutionInvariant(forged); } catch {}
    const record = JSON.parse(stderrWrite.mock.calls[0][0]);
    expect(record.violations).toContain('EXECUTION_TOKEN_INVALID');
    stderrWrite.mockRestore();
  });
});

// ── Violation logging ─────────────────────────────────────────────────────────

describe('assertExecutionInvariant — violation is logged to stderr before throw', () => {
  let stderrOutput;
  let stderrWrite;

  beforeEach(() => {
    stderrOutput = [];
    stderrWrite  = jest.spyOn(process.stderr, 'write')
      .mockImplementation(chunk => { stderrOutput.push(chunk); return true; });
  });

  afterEach(() => {
    stderrWrite.mockRestore();
  });

  test('CRITICAL event written to stderr synchronously before throw', () => {
    let threw = false;
    try {
      assertExecutionInvariant(null, 'test-call-site');
    } catch {
      threw = true;
    }

    expect(threw).toBe(true);
    expect(stderrOutput.length).toBeGreaterThanOrEqual(1);

    const record = JSON.parse(stderrOutput[0]);
    expect(record.severity).toBe('CRITICAL');
    expect(record.eventType).toBe('EXECUTION_INVARIANT_VIOLATED');
    expect(record.callSite).toBe('test-call-site');
    expect(Array.isArray(record.violations)).toBe(true);
    expect(record.violations.length).toBeGreaterThan(0);
  });

  test('violations array names each specific failure', () => {
    try {
      assertExecutionInvariant({
        verified:    false,
        requestHash: 'not-hex',
        artifactId:  '',
      });
    } catch {}

    const record = JSON.parse(stderrOutput[0]);
    expect(record.violations).toContain('VERIFIED_NOT_TRUE');
    expect(record.violations).toContain('REQUEST_HASH_INVALID');
    expect(record.violations).toContain('ARTIFACT_ID_MISSING');
  });

  test('stats snapshot in log reflects cumulative counts at violation time', () => {
    assertExecutionInvariant(buildValidCtx());  // verified call first
    try { assertExecutionInvariant(null); } catch {}

    const record = JSON.parse(stderrOutput[0]);
    expect(record.stats.totalAttempts).toBe(2);
    expect(record.stats.verifiedCalls).toBe(1);
    expect(record.stats.violationCount).toBe(1);
  });

  test('log is written even when caller catches the error', () => {
    // Simulate a developer bug: catch the throw and continue
    try { assertExecutionInvariant(undefined); } catch { /* swallowed */ }

    // The log entry must still exist
    expect(stderrOutput.length).toBeGreaterThanOrEqual(1);
    expect(JSON.parse(stderrOutput[0]).eventType).toBe('EXECUTION_INVARIANT_VIOLATED');
  });
});

// ── executeProviderCall enforces the invariant ────────────────────────────────

describe('executeProviderCall — invariant enforced before provider I/O', () => {
  const http = require('http');

  beforeEach(() => {
    resetStats();
  });

  test('no context → throws before any network I/O', async () => {
    const spy = jest.spyOn(http, 'request');
    const { executeProviderCall } = require('../execution');

    await expect(executeProviderCall('openai', {}, undefined))
      .rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('invalid context (verified:false) → throws before network I/O', async () => {
    const spy = jest.spyOn(http, 'request');
    const { executeProviderCall } = require('../execution');

    await expect(
      executeProviderCall('openai', {}, buildValidCtx({ verified: false })),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('forged signature → throws before network I/O', async () => {
    const spy = jest.spyOn(http, 'request');
    const { executeProviderCall } = require('../execution');
    const forged = { ...buildValidCtx(), signature: 'f'.repeat(64) };

    await expect(
      executeProviderCall('openai', {}, forged),
    ).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');

    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('violation increments the global violationCount via the shared guard', async () => {
    const { executeProviderCall } = require('../execution');
    try { await executeProviderCall('openai', {}, null); } catch {}
    expect(getStats().violationCount).toBe(1);
    expect(getStats().verifiedCalls).toBe(0);
  });

  test('valid context increments verifiedCalls (even if provider fails)', async () => {
    // executeProviderCall will try to reach a provider; it will fail with
    // PROVIDER_UNAVAILABLE (unknown provider name) but the invariant passes.
    const { executeProviderCall } = require('../execution');
    try { await executeProviderCall('unknown-provider', {}, buildValidCtx()); } catch {}
    expect(getStats().verifiedCalls).toBe(1);
    expect(getStats().violationCount).toBe(0);
  });
});

// ── Stats identity invariant ──────────────────────────────────────────────────

describe('getStats — identity invariant', () => {
  test('totalAttempts === verifiedCalls + violationCount at all times', () => {
    const ops = [
      () => assertExecutionInvariant(buildValidCtx()),
      () => { try { assertExecutionInvariant(null); } catch {} },
      () => assertExecutionInvariant(buildValidCtx()),
      () => { try { assertExecutionInvariant(buildValidCtx({ verified: false })); } catch {} },
      () => assertExecutionInvariant(buildValidCtx()),
    ];

    for (const op of ops) {
      op();
      const { totalAttempts, verifiedCalls, violationCount } = getStats();
      expect(totalAttempts).toBe(verifiedCalls + violationCount);
    }
  });
});
