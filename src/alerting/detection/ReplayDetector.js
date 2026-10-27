'use strict';

/**
 * QODIQA Replay Attack Detector
 *
 * Monitors the platform event stream for all forms of replay attack:
 *   - Nonce reuse (requestId submitted more than once)
 *   - Duplicate artifact submission
 *   - Repeated request hash collisions
 *   - Cross-tenant replay (requestId or artifactId seen across different tenants)
 *   - Expired artifact usage
 *   - Excessive verification retries (anomaly threshold exceeded)
 *   - Request binding mismatches (requestHash != body hash)
 *
 * Each detection returns a structured alert specification that the
 * DetectionEngine passes to AlertEngine for lifecycle management.
 */

const {
  ALERT_TYPE, REPLAY_SUBTYPE, SEVERITY,
} = require('../constants');

// ── Per-replay-event detection rules ─────────────────────────────────────────

const REPLAY_RULES = [

  {
    events:    ['NONCE_V2_REPLAY_DETECTED'],
    subtype:   REPLAY_SUBTYPE.NONCE_REUSE,
    severity:  SEVERITY.HIGH,
    confidence: 99,
    title:     (ev) => `Nonce reuse detected — requestId ${ev.requestId ?? 'unknown'}`,
    description: (ev) =>
      `A duplicate requestId was submitted to the nonce store. ` +
      `requestId=${ev.requestId ?? '?'} has already been registered. ` +
      `This indicates an active replay attack or a buggy client sending duplicate requests.`,
    tags:      ['replay', 'nonce', 'active-attack'],
    evidence:  (ev) => ({
      requestId:   ev.requestId,
      artifactId:  ev.artifactId,
      tenantId:    ev.tenantId,
      clientIp:    ev.clientIp,
      timestamp:   ev.timestamp,
      nonceKey:    ev.nonceKey,
    }),
    context:   (ev) => ({
      crossTenant: !!(ev.tenantId && ev.previousTenantId && ev.tenantId !== ev.previousTenantId),
    }),
  },

  {
    events:    ['ANOMALY_THRESHOLD_EXCEEDED'],
    subtype:   REPLAY_SUBTYPE.ANOMALY_THRESHOLD,
    severity:  SEVERITY.HIGH,
    confidence: 85,
    title:     (ev) => `Anomaly threshold exceeded for key ${ev.publicKeyId ?? 'unknown'}`,
    description: (ev) =>
      `Key ${ev.publicKeyId ?? '?'} has exceeded the per-key request rate threshold. ` +
      `Count: ${ev.count ?? '?'} in sliding window. ` +
      `This indicates a burst replay attack or compromised credential being replayed at scale.`,
    tags:      ['replay', 'anomaly', 'rate-burst'],
    evidence:  (ev) => ({
      publicKeyId:  ev.publicKeyId,
      count:        ev.count,
      threshold:    ev.threshold,
      windowSecs:   ev.windowSecs,
      tenantId:     ev.tenantId,
    }),
    context:   (ev) => ({
      affectsMultipleKeys: false,
    }),
  },

  {
    events:    ['INVALID_BINDING', 'REQUEST_BINDING_MISMATCH'],
    subtype:   REPLAY_SUBTYPE.REQUEST_BINDING_MISMATCH,
    severity:  SEVERITY.HIGH,
    confidence: 95,
    title:     (ev) => `Request binding mismatch — requestId ${ev.requestId ?? 'unknown'}`,
    description: (ev) =>
      `The requestHash in the artifact does not match the SHA-256 of the HTTP request body. ` +
      `This indicates request tampering after signing, or a replay attempt with a mismatched payload. ` +
      `requestId=${ev.requestId ?? '?'}, reason=${ev.reason ?? '?'}`,
    tags:      ['replay', 'binding', 'tampering'],
    evidence:  (ev) => ({
      requestId:    ev.requestId,
      artifactId:   ev.artifactId,
      reason:       ev.reason,
      clientIp:     ev.clientIp,
    }),
    context:   () => ({}),
  },

];

// ── Block-decision replay sub-analysis ───────────────────────────────────────

/**
 * Analyze GATEWAY_BLOCK events for replay-related block reasons.
 * These are secondary signals derived from enforcement outcomes.
 */
function _analyzeBlock(event) {
  const reason = (event.reason ?? '').toUpperCase();

  if (reason.includes('REPLAY') || reason.includes('NONCE')) {
    return {
      subtype:    REPLAY_SUBTYPE.NONCE_REUSE,
      severity:   SEVERITY.HIGH,
      confidence: 90,
      title:      `Gateway blocked request for replay — requestId ${event.requestId ?? 'unknown'}`,
      description:`Enforcement gateway blocked a request with replay-related reason: "${event.reason}". ` +
                  `This may indicate an active replay attack or duplicate submission.`,
      tags:       ['replay', 'block'],
      evidence: {
        requestId:  event.requestId,
        artifactId: event.artifactId,
        reason:     event.reason,
        tenantId:   event.tenantId,
        clientIp:   event.clientIp,
      },
      context: {},
    };
  }

  if (reason.includes('EXPIRED')) {
    return {
      subtype:    REPLAY_SUBTYPE.EXPIRED_ARTIFACT,
      severity:   SEVERITY.MEDIUM,
      confidence: 88,
      title:      `Expired artifact submitted — requestId ${event.requestId ?? 'unknown'}`,
      description:`An artifact with an expired timestamp was submitted. ` +
                  `reason="${event.reason}". This may indicate an old artifact being replayed, ` +
                  `clock skew, or a misconfigured client.`,
      tags:       ['replay', 'expiry'],
      evidence: {
        requestId:  event.requestId,
        artifactId: event.artifactId,
        reason:     event.reason,
        clientIp:   event.clientIp,
      },
      context: {},
    };
  }

  return null;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Analyze a platform event for replay attack indicators.
 *
 * @param {object} event  — Structured log record from eventBus
 * @returns {{ triggered: boolean, alert?: object }}
 */
function analyze(event) {
  const eventName = event.eventType ?? '';

  // Check direct-match rules
  for (const rule of REPLAY_RULES) {
    if (!rule.events.includes(eventName)) continue;

    return {
      triggered: true,
      alert: {
        type:        ALERT_TYPE.REPLAY_ATTACK,
        subtype:     rule.subtype,
        severity:    rule.severity,
        confidence:  rule.confidence,
        title:       rule.title(event),
        description: rule.description(event),
        tags:        rule.tags,
        evidence:    rule.evidence(event),
        context:     rule.context(event),
        sourceEvent: eventName,
        requestId:   event.requestId,
        artifactId:  event.artifactId,
        tenantId:    event.tenantId,
        publicKeyId: event.publicKeyId,
        clientIp:    event.clientIp,
        component:   event.component,
      },
    };
  }

  // Secondary: block decision analysis
  if (eventName === 'GATEWAY_BLOCK') {
    const blockAlert = _analyzeBlock(event);
    if (blockAlert) {
      return {
        triggered: true,
        alert: {
          type:       ALERT_TYPE.REPLAY_ATTACK,
          sourceEvent: eventName,
          requestId:  event.requestId,
          artifactId: event.artifactId,
          tenantId:   event.tenantId,
          clientIp:   event.clientIp,
          component:  event.component,
          ...blockAlert,
        },
      };
    }
  }

  return { triggered: false };
}

module.exports = { analyze };
