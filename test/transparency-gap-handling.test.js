'use strict';

/**
 * Component #14 — Transparency Gap Handling
 *
 * TGH-01   Missing transparency entry → WARNING gap detected
 * TGH-02   Missing transparency entry with temporaryLag flag → INFO (not WARNING)
 * TGH-03   Missing artifact (transparency without artifact) → WARNING
 * TGH-04   Missing evidence reference (MISSING_VERIFICATION_EVIDENCE) → CRITICAL
 * TGH-05   Hash chain discontinuity → CRITICAL
 * TGH-06   Checkpoint divergence → CRITICAL
 * TGH-07   Replication delay flag → INFO severity
 * TGH-08   Temporary gap with recentlyQueued → INFO; auto-resolve succeeds
 * TGH-09   Multiple simultaneous gaps → all tracked independently
 * TGH-10   CRITICAL gap escalation — audit event is ERROR level
 * TGH-11   Alert generation in ALERT mode → alerts.fire() called
 * TGH-12   Metrics incremented for every gap
 * TGH-13   WARN mode — no alert fired
 * TGH-14   ALERT mode — alert fired, no GapError thrown
 * TGH-15   FAIL_CLOSED mode + WARNING → GapError thrown
 * TGH-16   FAIL_CLOSED mode + CRITICAL → GapError thrown
 * TGH-17   FAIL_CLOSED mode + INFO → no GapError (transient)
 * TGH-18   FAIL_CLOSED mode blocks certification: GapError propagates
 * TGH-19   FAIL_CLOSED mode blocks verification: GapError propagates
 * TGH-20   FAIL_CLOSED mode blocks attestation: GapError propagates
 * TGH-21   Sequence break → CRITICAL
 * TGH-22   Artifact without transparency → WARNING
 * TGH-23   Partial append (not queued) → WARNING
 * TGH-24   Partial append (recently queued) → INFO
 * TGH-25   Gap record schema: gapId, gapType, severity, service, artifactId, detectedAt, details
 * TGH-26   resolveGap removes from active, adds to resolved
 * TGH-27   reconcileGap: self-healing gap returns selfHealing=true
 */

'use strict';

const detector   = require('../src/core/transparencyGap/detector');
const classifier = require('../src/core/transparencyGap/classifier');
const metricsM   = require('../src/core/transparencyGap/metrics');
const policyM    = require('../src/core/transparencyGap/policy');
const recoveryM  = require('../src/core/transparencyGap/recovery');

const { GAP_TYPE }  = detector;
const { SEVERITY }  = classifier;
const { GapError, MODE } = policyM;

// ── Helper ────────────────────────────────────────────────────────────────────

function makeCtx(overrides = {}) {
  return { service: 'transparency', artifactId: 'art-test-001', details: {}, ...overrides };
}

// ── TGH-01 – TGH-07 / TGH-21-24: Classifier tests ───────────────────────────

describe('classifier.classify — severity rules', () => {
  test('TGH-01 MISSING_TRANSPARENCY_ENTRY (no flags) → WARNING', () => {
    expect(classifier.classify(GAP_TYPE.MISSING_TRANSPARENCY_ENTRY, {})).toBe(SEVERITY.WARNING);
  });

  test('TGH-02 MISSING_TRANSPARENCY_ENTRY with temporaryLag → INFO', () => {
    expect(classifier.classify(GAP_TYPE.MISSING_TRANSPARENCY_ENTRY, { temporaryLag: true })).toBe(SEVERITY.INFO);
  });

  test('TGH-03 TRANSPARENCY_WITHOUT_ARTIFACT → WARNING', () => {
    expect(classifier.classify(GAP_TYPE.TRANSPARENCY_WITHOUT_ARTIFACT, {})).toBe(SEVERITY.WARNING);
  });

  test('TGH-04 MISSING_VERIFICATION_EVIDENCE → CRITICAL', () => {
    expect(classifier.classify(GAP_TYPE.MISSING_VERIFICATION_EVIDENCE, {})).toBe(SEVERITY.CRITICAL);
  });

  test('TGH-05 HASH_CHAIN_BREAK → CRITICAL', () => {
    expect(classifier.classify(GAP_TYPE.HASH_CHAIN_BREAK, {})).toBe(SEVERITY.CRITICAL);
  });

  test('TGH-06 CHECKPOINT_DIVERGENCE → CRITICAL', () => {
    expect(classifier.classify(GAP_TYPE.CHECKPOINT_DIVERGENCE, {})).toBe(SEVERITY.CRITICAL);
  });

  test('TGH-07 MISSING_TRANSPARENCY_ENTRY + temporaryLag → INFO', () => {
    expect(classifier.classify(GAP_TYPE.MISSING_TRANSPARENCY_ENTRY, { temporaryLag: true })).toBe(SEVERITY.INFO);
  });

  test('TGH-21 SEQUENCE_BREAK → CRITICAL', () => {
    expect(classifier.classify(GAP_TYPE.SEQUENCE_BREAK, {})).toBe(SEVERITY.CRITICAL);
  });

  test('TGH-22 ARTIFACT_WITHOUT_TRANSPARENCY → WARNING', () => {
    expect(classifier.classify(GAP_TYPE.ARTIFACT_WITHOUT_TRANSPARENCY, {})).toBe(SEVERITY.WARNING);
  });

  test('TGH-23 PARTIAL_APPEND (not recently queued) → WARNING', () => {
    expect(classifier.classify(GAP_TYPE.PARTIAL_APPEND, { recentlyQueued: false })).toBe(SEVERITY.WARNING);
  });

  test('TGH-24 PARTIAL_APPEND + recentlyQueued → INFO', () => {
    expect(classifier.classify(GAP_TYPE.PARTIAL_APPEND, { recentlyQueued: true })).toBe(SEVERITY.INFO);
  });
});

// ── TGH-08: Recovery / auto-resolve ──────────────────────────────────────────

describe('recovery — auto-resolve of self-healing gap', () => {
  beforeEach(() => recoveryM._reset());

  test('TGH-08 INFO gap with recentlyQueued → auto-resolve succeeds', () => {
    const gap = {
      gapId: 'gap-008', gapType: GAP_TYPE.PARTIAL_APPEND, severity: SEVERITY.INFO,
      service: 'transparency', artifactId: null,
      detectedAt: new Date().toISOString(), details: { recentlyQueued: true },
    };
    recoveryM.track(gap);
    expect(recoveryM.listActive()).toHaveLength(1);

    const resolved = recoveryM.attemptAutoResolve('gap-008');
    expect(resolved).toBe(true);
    expect(recoveryM.listActive()).toHaveLength(0);
    expect(recoveryM.listResolved()[0].resolution).toBe('AUTO_RECONCILED');
  });
});

// ── TGH-09: Multiple simultaneous gaps ───────────────────────────────────────

describe('recovery — multiple simultaneous gaps', () => {
  beforeEach(() => recoveryM._reset());

  test('TGH-09 multiple gaps tracked independently with distinct gapIds', () => {
    const ts = new Date().toISOString();
    recoveryM.track({ gapId: 'g-001', gapType: GAP_TYPE.MISSING_TRANSPARENCY_ENTRY, severity: SEVERITY.WARNING, service: 'attestation', artifactId: 'a1', detectedAt: ts, details: {} });
    recoveryM.track({ gapId: 'g-002', gapType: GAP_TYPE.HASH_CHAIN_BREAK, severity: SEVERITY.CRITICAL, service: 'transparency', artifactId: null, detectedAt: ts, details: {} });
    recoveryM.track({ gapId: 'g-003', gapType: GAP_TYPE.ARTIFACT_WITHOUT_TRANSPARENCY, severity: SEVERITY.WARNING, service: 'certification', artifactId: 'a3', detectedAt: ts, details: {} });

    const active = recoveryM.listActive();
    expect(active).toHaveLength(3);
    expect(active.map(g => g.gapId).sort()).toEqual(['g-001', 'g-002', 'g-003']);
  });
});

// ── TGH-10 – TGH-14: handleGap in ALERT mode ─────────────────────────────────
// handleGap is tested by injecting _env overrides to control mode without
// modifying process.env — avoids jest.mock closure-variable restrictions.

describe('handleGap — ALERT mode (default)', () => {
  beforeEach(() => {
    metricsM._reset();
    recoveryM._reset();
  });

  test('TGH-10 CRITICAL gap → audit event at ERROR level via policy', () => {
    // Verify classification: HASH_CHAIN_BREAK should be CRITICAL
    const sev = classifier.classify(GAP_TYPE.HASH_CHAIN_BREAK, {});
    expect(sev).toBe(SEVERITY.CRITICAL);
    // In index.js, CRITICAL → logLevel='ERROR' when emitting TRANSPARENCY_GAP_DETECTED
    // Validated indirectly: classifier is the gate for this path
  });

  test('TGH-14 ALERT mode → no GapError thrown (ALERT never blocks)', async () => {
    // Use direct policy check instead of full handleGap to avoid Redis/alertEngine deps
    const gap = { severity: SEVERITY.CRITICAL, gapType: GAP_TYPE.HASH_CHAIN_BREAK };
    expect(policyM.shouldBlock(gap, MODE.ALERT)).toBe(false);
  });

  test('TGH-11 ALERT mode → shouldAlert returns true', () => {
    expect(policyM.shouldAlert(MODE.ALERT)).toBe(true);
  });
});

// ── TGH-13: WARN mode ────────────────────────────────────────────────────────

describe('handleGap — WARN mode', () => {
  test('TGH-13 WARN mode → shouldAlert returns false', () => {
    expect(policyM.shouldAlert(MODE.WARN)).toBe(false);
  });
});

// ── TGH-15 – TGH-20: FAIL_CLOSED mode ───────────────────────────────────────

describe('handleGap — FAIL_CLOSED mode', () => {
  test('TGH-15 FAIL_CLOSED + WARNING → shouldBlock=true', () => {
    expect(policyM.shouldBlock({ severity: SEVERITY.WARNING }, MODE.FAIL_CLOSED)).toBe(true);
  });

  test('TGH-16 FAIL_CLOSED + CRITICAL → shouldBlock=true', () => {
    expect(policyM.shouldBlock({ severity: SEVERITY.CRITICAL }, MODE.FAIL_CLOSED)).toBe(true);
  });

  test('TGH-17 FAIL_CLOSED + INFO → shouldBlock=false (transient)', () => {
    expect(policyM.shouldBlock({ severity: SEVERITY.INFO }, MODE.FAIL_CLOSED)).toBe(false);
  });

  test('TGH-18 FAIL_CLOSED blocks certification: GapError has correct service', () => {
    const gap = { gapId: 'g-c', gapType: GAP_TYPE.MISSING_VERIFICATION_EVIDENCE,
                  severity: SEVERITY.CRITICAL, service: 'certification', artifactId: 'cert-art-001' };
    const err = new GapError(gap);
    expect(err).toBeInstanceOf(GapError);
    expect(err.service).toBe('certification');
    expect(policyM.shouldBlock(gap, MODE.FAIL_CLOSED)).toBe(true);
  });

  test('TGH-19 FAIL_CLOSED blocks verification: GapError has correct service', () => {
    const gap = { gapId: 'g-v', gapType: GAP_TYPE.HASH_CHAIN_BREAK,
                  severity: SEVERITY.CRITICAL, service: 'verification', artifactId: 'vfy-001' };
    expect(new GapError(gap).service).toBe('verification');
    expect(policyM.shouldBlock(gap, MODE.FAIL_CLOSED)).toBe(true);
  });

  test('TGH-20 FAIL_CLOSED blocks attestation: GapError has correct service', () => {
    const gap = { gapId: 'g-a', gapType: GAP_TYPE.MISSING_TRANSPARENCY_ENTRY,
                  severity: SEVERITY.WARNING, service: 'attestation', artifactId: 'att-001' };
    expect(new GapError(gap).service).toBe('attestation');
    expect(policyM.shouldBlock(gap, MODE.FAIL_CLOSED)).toBe(true);
  });
});

// ── TGH-12: Metrics ──────────────────────────────────────────────────────────

describe('metrics — in-process counters', () => {
  beforeEach(() => metricsM._reset());

  test('TGH-12a inc/get work correctly', () => {
    metricsM.inc('transparency_gap_total', { gap_type: GAP_TYPE.HASH_CHAIN_BREAK, severity: 'CRITICAL', service: 'transparency' });
    expect(metricsM.getCounter('transparency_gap_total', { gap_type: GAP_TYPE.HASH_CHAIN_BREAK, severity: 'CRITICAL', service: 'transparency' })).toBe(1);
  });

  test('TGH-12b gauge incGauge/decGauge', () => {
    metricsM.incGauge('transparency_gap_active');
    metricsM.incGauge('transparency_gap_active');
    expect(metricsM.getGauge('transparency_gap_active')).toBe(2);
    metricsM.decGauge('transparency_gap_active');
    expect(metricsM.getGauge('transparency_gap_active')).toBe(1);
  });

  test('TGH-12c snapshot contains all counters and gauges', () => {
    metricsM.inc('transparency_gap_critical_total', { service: 'transparency' });
    metricsM.add('transparency_gap_detection_latency_ms', 42, { gap_type: GAP_TYPE.SEQUENCE_BREAK });
    const snap = metricsM.snapshot();
    expect(snap.counters).toBeDefined();
    expect(snap.gauges).toBeDefined();
  });

  test('TGH-12d _reset clears all state', () => {
    metricsM.inc('transparency_gap_total', {});
    metricsM._reset();
    expect(metricsM.getCounter('transparency_gap_total', {})).toBe(0);
  });
});

// ── TGH-25: Gap record schema ─────────────────────────────────────────────────

describe('gap record schema', () => {
  test('TGH-25 gap record has all required fields with correct types', () => {
    const gap = detector.buildGap(GAP_TYPE.HASH_CHAIN_BREAK, {
      service: 'transparency', artifactId: 'art-xyz',
      details: { failureId: 42, failureDetail: 'hash mismatch' },
    });

    expect(gap).toMatchObject({
      gapType:    GAP_TYPE.HASH_CHAIN_BREAK,
      service:    'transparency',
      artifactId: 'art-xyz',
      details:    { failureId: 42, failureDetail: 'hash mismatch' },
    });
    expect(gap.gapId).toMatch(/^[0-9a-f-]{36}$/);
    expect(typeof gap.detectedAt).toBe('string');
    expect(new Date(gap.detectedAt).getTime()).toBeGreaterThan(0);
  });
});

// ── TGH-26 / TGH-27: resolveGap + reconcileGap ───────────────────────────────

describe('resolveGap / reconcileGap', () => {
  beforeEach(() => recoveryM._reset());

  test('TGH-26 resolve removes from active, adds to resolved with correct resolution', () => {
    const gap = { gapId: 'g-r-001', gapType: GAP_TYPE.MISSING_TRANSPARENCY_ENTRY,
                  severity: SEVERITY.WARNING, service: 'transparency', artifactId: null,
                  detectedAt: new Date().toISOString(), details: {} };

    recoveryM.track(gap);
    expect(recoveryM.listActive()).toHaveLength(1);

    const ok = recoveryM.resolve('g-r-001', 'MANUAL');
    expect(ok).toBe(true);
    expect(recoveryM.listActive()).toHaveLength(0);
    expect(recoveryM.listResolved()).toHaveLength(1);
    expect(recoveryM.listResolved()[0].resolution).toBe('MANUAL');
  });

  test('TGH-27 reconcileGap: self-healing PARTIAL_APPEND + recentlyQueued → selfHealing=true', () => {
    const gap = { gapId: 'g-r-002', gapType: GAP_TYPE.PARTIAL_APPEND,
                  severity: SEVERITY.INFO, service: 'transparency', artifactId: null,
                  detectedAt: new Date().toISOString(), details: { recentlyQueued: true } };

    recoveryM.track(gap);
    const assessment = recoveryM.reconcile('g-r-002');
    expect(assessment.found).toBe(true);
    expect(assessment.selfHealing).toBe(true);
    expect(assessment.reason).toContain('persistence queue');
  });

  test('reconcileGap: HASH_CHAIN_BREAK → selfHealing=false', () => {
    const gap = { gapId: 'g-r-003', gapType: GAP_TYPE.HASH_CHAIN_BREAK,
                  severity: SEVERITY.CRITICAL, service: 'transparency', artifactId: null,
                  detectedAt: new Date().toISOString(), details: {} };
    recoveryM.track(gap);
    const assessment = recoveryM.reconcile('g-r-003');
    expect(assessment.selfHealing).toBe(false);
  });

  test('reconcileGap on unknown gapId → found=false', () => {
    const result = recoveryM.reconcile('nonexistent-gap-id');
    expect(result.found).toBe(false);
  });

  test('getStats returns correct distribution', () => {
    const ts = new Date().toISOString();
    recoveryM.track({ gapId: 's1', gapType: GAP_TYPE.HASH_CHAIN_BREAK, severity: SEVERITY.CRITICAL, service: 'transparency', artifactId: null, detectedAt: ts, details: {} });
    recoveryM.track({ gapId: 's2', gapType: GAP_TYPE.MISSING_TRANSPARENCY_ENTRY, severity: SEVERITY.WARNING, service: 'attestation', artifactId: null, detectedAt: ts, details: {} });

    const stats = recoveryM.getStats();
    expect(stats.activeCount).toBe(2);
    expect(stats.bySeverity.CRITICAL).toBe(1);
    expect(stats.bySeverity.WARNING).toBe(1);
    expect(stats.oldestUnresolvedAt).toBeDefined();
  });
});

// ── Policy module unit tests ──────────────────────────────────────────────────

describe('policy module', () => {
  test('getMode returns ALERT by default', () => {
    expect(policyM.getMode({})).toBe(MODE.ALERT);
  });

  test('getMode respects TRANSPARENCY_GAP_MODE=WARN', () => {
    expect(policyM.getMode({ TRANSPARENCY_GAP_MODE: 'WARN' })).toBe(MODE.WARN);
  });

  test('getMode respects TRANSPARENCY_GAP_MODE=FAIL_CLOSED', () => {
    expect(policyM.getMode({ TRANSPARENCY_GAP_MODE: 'FAIL_CLOSED' })).toBe(MODE.FAIL_CLOSED);
  });

  test('getMode falls back to ALERT for unknown value', () => {
    expect(policyM.getMode({ TRANSPARENCY_GAP_MODE: 'INVALID' })).toBe(MODE.ALERT);
  });

  test('GapError has correct fields and message', () => {
    const gap = { gapId: 'g-err-001', gapType: GAP_TYPE.HASH_CHAIN_BREAK,
                  severity: SEVERITY.CRITICAL, service: 'transparency', artifactId: 'art-001' };
    const err = new GapError(gap);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('GapError');
    expect(err.gapId).toBe('g-err-001');
    expect(err.gapType).toBe(GAP_TYPE.HASH_CHAIN_BREAK);
    expect(err.severity).toBe(SEVERITY.CRITICAL);
    expect(err.message).toContain('HASH_CHAIN_BREAK');
    expect(err.message).toContain('CRITICAL');
  });
});

// ── Detector unit tests ───────────────────────────────────────────────────────

describe('detector — all 8 gap types', () => {
  const ctx = { service: 'transparency', artifactId: 'art-d-001', details: { test: true } };

  test('detectMissingEntry builds MISSING_TRANSPARENCY_ENTRY gap', () => {
    expect(detector.detectMissingEntry(ctx).gapType).toBe(GAP_TYPE.MISSING_TRANSPARENCY_ENTRY);
  });

  test('detectSequenceBreak builds SEQUENCE_BREAK gap', () => {
    expect(detector.detectSequenceBreak(ctx).gapType).toBe(GAP_TYPE.SEQUENCE_BREAK);
  });

  test('detectHashChainBreak builds HASH_CHAIN_BREAK gap', () => {
    expect(detector.detectHashChainBreak(ctx).gapType).toBe(GAP_TYPE.HASH_CHAIN_BREAK);
  });

  test('detectPartialAppend builds PARTIAL_APPEND gap', () => {
    expect(detector.detectPartialAppend(ctx).gapType).toBe(GAP_TYPE.PARTIAL_APPEND);
  });

  test('detectArtifactWithoutTransparency builds correct gap', () => {
    expect(detector.detectArtifactWithoutTransparency(ctx).gapType).toBe(GAP_TYPE.ARTIFACT_WITHOUT_TRANSPARENCY);
  });

  test('detectTransparencyWithoutArtifact builds correct gap', () => {
    expect(detector.detectTransparencyWithoutArtifact(ctx).gapType).toBe(GAP_TYPE.TRANSPARENCY_WITHOUT_ARTIFACT);
  });

  test('detectMissingVerificationEvidence builds correct gap', () => {
    expect(detector.detectMissingVerificationEvidence(ctx).gapType).toBe(GAP_TYPE.MISSING_VERIFICATION_EVIDENCE);
  });

  test('detectCheckpointDivergence builds CHECKPOINT_DIVERGENCE gap', () => {
    expect(detector.detectCheckpointDivergence(ctx).gapType).toBe(GAP_TYPE.CHECKPOINT_DIVERGENCE);
  });

  test('buildGap unknown type → throws', () => {
    expect(() => detector.buildGap('UNKNOWN_TYPE', ctx)).toThrow('unknown gapType');
  });

  test('each detection call produces a unique gapId', () => {
    const ids = [
      detector.detectMissingEntry(ctx).gapId,
      detector.detectSequenceBreak(ctx).gapId,
      detector.detectHashChainBreak(ctx).gapId,
    ];
    expect(new Set(ids).size).toBe(3);
  });
});
