'use strict';

/**
 * Transparency Gap Handling — Public API — Component #14
 *
 * Single entry point for all transparency gap detection, classification,
 * alerting, policy enforcement, and reconciliation.
 *
 * PRIMARY API
 *   handleGap(gapType, context)    — detect, classify, log, metric, alert, enforce
 *
 * SHORTHAND DETECTORS
 *   detectMissingEntry(ctx)
 *   detectSequenceBreak(ctx)
 *   detectHashChainBreak(ctx)
 *   detectPartialAppend(ctx)
 *   detectArtifactWithoutTransparency(ctx)
 *   detectTransparencyWithoutArtifact(ctx)
 *   detectMissingVerificationEvidence(ctx)
 *   detectCheckpointDivergence(ctx)
 *
 * ADMIN / OPS
 *   getStats()          — active gaps, severity distribution, resolution rate
 *   listActiveGaps()    — full list of unresolved gaps
 *   resolveGap(gapId)   — manually resolve a gap
 *   reconcileGap(gapId) — reconciliation assessment for a gap
 *
 * CONFIGURATION
 *   TRANSPARENCY_GAP_MODE=WARN|ALERT|FAIL_CLOSED  (default: ALERT)
 *
 * handleGap() return value:
 *   { gap: GapRecord, blocked: false }
 *   — or throws GapError when mode=FAIL_CLOSED and severity is WARNING|CRITICAL
 */

const detector  = require('./detector');
const classifier = require('./classifier');
const metricsModule = require('./metrics');
const alerts    = require('./alerts');
const policy    = require('./policy');
const recovery  = require('./recovery');
const obsMetrics = require('../../observability/metrics');
const { emit }  = require('../../../services/logger');

const { GAP_TYPE }  = detector;
const { SEVERITY }  = classifier;
const { GapError }  = policy;

const SOURCE = 'TRANSPARENCY_GAP';

// ── Primary API ───────────────────────────────────────────────────────────────

/**
 * Handle a detected transparency gap end-to-end.
 *
 * 1. Build the raw gap record (via detector)
 * 2. Classify severity (via classifier)
 * 3. Track in recovery store
 * 4. Emit audit event
 * 5. Increment metrics (internal + Prometheus)
 * 6. Apply policy: WARN → log only; ALERT → log + metric + alert; FAIL_CLOSED → + throw
 *
 * @param {string} gapType  — one of GAP_TYPE values
 * @param {object} context  — { service, artifactId?, details? }
 * @param {object} [opts]
 * @param {object} [opts._env]  — injectable env for tests
 * @returns {Promise<{ gap: object, blocked: false }>}
 * @throws {GapError}  when mode=FAIL_CLOSED and severity is WARNING or CRITICAL
 */
async function handleGap(gapType, context = {}, { _env } = {}) {
  const startMs = Date.now();

  // 1. Build raw gap record
  const rawGap   = detector.buildGap(gapType, context);

  // 2. Classify
  const severity = classifier.classify(gapType, context.details ?? {});
  const gap      = { ...rawGap, severity };

  // 3. Track
  recovery.track(gap);
  metricsModule.incGauge('transparency_gap_active');
  metricsModule.inc('transparency_gap_total', { gap_type: gapType, severity, service: gap.service });

  if (severity === SEVERITY.CRITICAL) {
    metricsModule.inc('transparency_gap_critical_total', { service: gap.service });
    // Prometheus critical counter
    try { obsMetrics.transparencyGapCriticalTotal?.inc({ service: gap.service }); } catch { /* infallible */ }
  }

  // Prometheus total counter
  try { obsMetrics.transparencyGapTotal?.inc({ gap_type: gapType, severity, service: gap.service }); } catch { /* infallible */ }

  // 4. Audit event
  const logLevel = severity === SEVERITY.CRITICAL ? 'ERROR'
                 : severity === SEVERITY.WARNING   ? 'WARN'
                 : 'INFO';
  emit(logLevel, 'TRANSPARENCY_GAP_DETECTED', {
    source:     SOURCE,
    gapId:      gap.gapId,
    gapType:    gap.gapType,
    severity:   gap.severity,
    service:    gap.service,
    artifactId: gap.artifactId,
    timestamp:  gap.detectedAt,
  });

  // 5. Metrics: detection latency
  const latencyMs = Date.now() - startMs;
  metricsModule.add('transparency_gap_detection_latency_ms', latencyMs, { gap_type: gapType });
  try { obsMetrics.transparencyGapDetectionLatencyMs?.observe({ gap_type: gapType }, latencyMs); } catch { /* infallible */ }

  // 6. Policy
  const mode = policy.getMode(_env);

  if (policy.shouldAlert(mode)) {
    alerts.fire(gap); // fire-and-forget, never await
    emit('INFO', 'TRANSPARENCY_GAP_ALERTED', {
      source:  SOURCE,
      gapId:   gap.gapId,
      gapType: gap.gapType,
      severity: gap.severity,
      service:  gap.service,
      timestamp: gap.detectedAt,
    });
  }

  if (policy.shouldBlock(gap, mode)) {
    emit('ERROR', 'TRANSPARENCY_GAP_FAIL_CLOSED', {
      source:    SOURCE,
      gapId:     gap.gapId,
      gapType:   gap.gapType,
      severity:  gap.severity,
      service:   gap.service,
      artifactId: gap.artifactId,
      timestamp:  gap.detectedAt,
    });
    throw new GapError(gap);
  }

  return { gap, blocked: false };
}

// ── Shorthand detector wrappers ───────────────────────────────────────────────
// Each shorthand builds the gap AND dispatches through handleGap.

async function detectMissingEntry(ctx, opts)                  { return handleGap(GAP_TYPE.MISSING_TRANSPARENCY_ENTRY,    ctx, opts); }
async function detectSequenceBreak(ctx, opts)                 { return handleGap(GAP_TYPE.SEQUENCE_BREAK,                ctx, opts); }
async function detectHashChainBreak(ctx, opts)                { return handleGap(GAP_TYPE.HASH_CHAIN_BREAK,              ctx, opts); }
async function detectPartialAppend(ctx, opts)                 { return handleGap(GAP_TYPE.PARTIAL_APPEND,               ctx, opts); }
async function detectArtifactWithoutTransparency(ctx, opts)   { return handleGap(GAP_TYPE.ARTIFACT_WITHOUT_TRANSPARENCY, ctx, opts); }
async function detectTransparencyWithoutArtifact(ctx, opts)   { return handleGap(GAP_TYPE.TRANSPARENCY_WITHOUT_ARTIFACT, ctx, opts); }
async function detectMissingVerificationEvidence(ctx, opts)   { return handleGap(GAP_TYPE.MISSING_VERIFICATION_EVIDENCE, ctx, opts); }
async function detectCheckpointDivergence(ctx, opts)          { return handleGap(GAP_TYPE.CHECKPOINT_DIVERGENCE,         ctx, opts); }

// ── Admin / ops ───────────────────────────────────────────────────────────────

/**
 * @returns {object}  Aggregate gap stats for admin tooling
 */
function getStats() {
  return {
    ...recovery.getStats(),
    metricsSnapshot: metricsModule.snapshot(),
  };
}

/**
 * @returns {object[]}  All currently unresolved gaps
 */
function listActiveGaps() {
  return recovery.listActive();
}

/**
 * Manually resolve a tracked gap.
 *
 * @param {string} gapId
 * @param {string} [resolution]
 * @returns {boolean}
 */
function resolveGap(gapId, resolution) {
  const ok = recovery.resolve(gapId, resolution);
  if (ok) {
    metricsModule.decGauge('transparency_gap_active');
    metricsModule.inc('transparency_gap_resolved_total');
    try { obsMetrics.transparencyGapResolvedTotal?.inc({}); } catch { /* infallible */ }
  }
  return ok;
}

/**
 * Attempt to auto-resolve a self-healing gap.
 *
 * @param {string} gapId
 * @returns {boolean}
 */
function autoResolveGap(gapId) {
  const ok = recovery.attemptAutoResolve(gapId);
  if (ok) {
    metricsModule.decGauge('transparency_gap_active');
    metricsModule.inc('transparency_gap_resolved_total');
    try { obsMetrics.transparencyGapResolvedTotal?.inc({}); } catch { /* infallible */ }
  }
  return ok;
}

/**
 * Reconciliation assessment for a gap.
 *
 * @param {string} gapId
 * @returns {{ found: boolean, selfHealing?: boolean, reason?: string, gap?: object }}
 */
function reconcileGap(gapId) {
  return recovery.reconcile(gapId);
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  // Primary
  handleGap,

  // Shorthand detectors
  detectMissingEntry,
  detectSequenceBreak,
  detectHashChainBreak,
  detectPartialAppend,
  detectArtifactWithoutTransparency,
  detectTransparencyWithoutArtifact,
  detectMissingVerificationEvidence,
  detectCheckpointDivergence,

  // Admin / ops
  getStats,
  listActiveGaps,
  resolveGap,
  autoResolveGap,
  reconcileGap,

  // Constants
  GAP_TYPE,
  GapError,
  MODE: policy.MODE,
};
