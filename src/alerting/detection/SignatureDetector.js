'use strict';

/**
 * QODIQA Signature Failure Detector
 *
 * Detects cryptographic integrity failures across the QODIQA platform:
 *   - Invalid Ed25519 signatures
 *   - Missing or malformed signature fields
 *   - Key resolution failures (unknown, revoked, expired keys)
 *   - Envelope binding failures (V2 signing domain violations)
 *   - Multiple active keys for a single tenant (key governance issue)
 *   - Tenant key provisioning failures
 *
 * Each detection produces a full forensic evidence package suitable for
 * cryptographic audit review and incident response.
 */

const { ALERT_TYPE, SIGNATURE_SUBTYPE, SEVERITY } = require('../constants');

// ── Signature failure event taxonomy ─────────────────────────────────────────

const SIGNATURE_RULES = [

  {
    events:   ['TENANT_KEY_EXPIRED_ACTIVE'],
    subtype:  SIGNATURE_SUBTYPE.EXPIRED_KEY,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    (ev) => `Active signing key expired — tenant ${ev.tenantId ?? ev.clientId ?? 'unknown'}`,
    description: (ev) =>
      `Tenant ${ev.tenantId ?? ev.clientId ?? '?'} has an active key (${ev.keyId ?? '?'}) that has ` +
      `passed its expiry date. The key is still in 'active' status and may be used to produce or ` +
      `verify artifacts. This is a key governance failure requiring immediate rotation.`,
    tags:     ['signature', 'key-expiry', 'governance'],
    evidence: (ev) => ({
      keyId:     ev.keyId,
      tenantId:  ev.tenantId ?? ev.clientId,
      expiresAt: ev.expiresAt,
      algorithm: ev.algorithm,
    }),
    context:  () => ({}),
  },

  {
    events:   ['MULTIPLE_ACTIVE_KEYS_DETECTED'],
    subtype:  SIGNATURE_SUBTYPE.MULTIPLE_ACTIVE_KEYS,
    severity: SEVERITY.MEDIUM,
    confidence: 100,
    title:    (ev) => `Multiple active keys detected — tenant ${ev.tenantId ?? ev.clientId ?? 'unknown'}`,
    description: (ev) =>
      `Tenant ${ev.tenantId ?? ev.clientId ?? '?'} has ${ev.count ?? 'multiple'} keys with ` +
      `'active' status simultaneously. Each tenant should have exactly one active signing key. ` +
      `This indicates an incomplete key rotation or key management inconsistency.`,
    tags:     ['signature', 'key-management', 'governance'],
    evidence: (ev) => ({
      tenantId:   ev.tenantId ?? ev.clientId,
      count:      ev.count,
      keyIds:     ev.keyIds,
    }),
    context:  () => ({ affectsMultipleKeys: true }),
  },

  {
    events:   ['TENANT_KEY_PROVISIONING_FAILED', 'TENANT_KEY_ROTATION_FAILED'],
    subtype:  SIGNATURE_SUBTYPE.KEY_MISMATCH,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Key provisioning failed — tenant ${ev.tenantId ?? ev.clientId ?? 'unknown'}`,
    description: (ev) =>
      `Failed to provision or rotate a signing key for tenant ` +
      `${ev.tenantId ?? ev.clientId ?? '?'}. ` +
      `error="${ev.error ?? ev.reason ?? 'unknown'}". ` +
      `Without a valid active key, all requests from this tenant will be blocked fail-closed. ` +
      `Immediate intervention required.`,
    tags:     ['signature', 'key-management', 'critical'],
    evidence: (ev) => ({
      tenantId: ev.tenantId ?? ev.clientId,
      error:    ev.error ?? ev.reason,
      event:    ev.eventType,
    }),
    context:  () => ({}),
  },

];

// ── Block-reason signature sub-analysis ──────────────────────────────────────

const BLOCK_REASON_PATTERNS = [
  {
    patterns:   [/SIGNATURE_INVALID/i, /INVALID_SIGNATURE/i, /sig.*fail/i, /verify.*fail/i],
    subtype:    SIGNATURE_SUBTYPE.INVALID_SIGNATURE,
    severity:   SEVERITY.HIGH,
    confidence: 92,
    tag:        'invalid-signature',
  },
  {
    patterns:   [/SIGNATURE_MISSING/i, /NO_SIGNATURE/i, /missing.*sig/i],
    subtype:    SIGNATURE_SUBTYPE.MISSING_SIGNATURE,
    severity:   SEVERITY.MEDIUM,
    confidence: 95,
    tag:        'missing-signature',
  },
  {
    patterns:   [/KEY_REVOKED/i, /revoked/i],
    subtype:    SIGNATURE_SUBTYPE.REVOKED_KEY,
    severity:   SEVERITY.HIGH,
    confidence: 98,
    tag:        'revoked-key',
  },
  {
    patterns:   [/KEY_EXPIRED/i, /expired.*key/i, /key.*expired/i],
    subtype:    SIGNATURE_SUBTYPE.EXPIRED_KEY,
    severity:   SEVERITY.MEDIUM,
    confidence: 95,
    tag:        'expired-key',
  },
  {
    patterns:   [/UNKNOWN_KEY/i, /key.*not.*found/i, /NO_SUCH_KEY/i],
    subtype:    SIGNATURE_SUBTYPE.UNKNOWN_KEY,
    severity:   SEVERITY.HIGH,
    confidence: 90,
    tag:        'unknown-key',
  },
  {
    patterns:   [/MALFORMED/i, /INVALID_ARTIFACT/i, /bad.*base64/i, /decode.*fail/i],
    subtype:    SIGNATURE_SUBTYPE.MALFORMED_ARTIFACT,
    severity:   SEVERITY.MEDIUM,
    confidence: 85,
    tag:        'malformed',
  },
  {
    patterns:   [/ENVELOPE/i, /BINDING/i, /domain.*mismatch/i],
    subtype:    SIGNATURE_SUBTYPE.ENVELOPE_BINDING_FAILURE,
    severity:   SEVERITY.HIGH,
    confidence: 90,
    tag:        'envelope-binding',
  },
];

function _analyzeBlockReason(event) {
  const reason = (event.reason ?? '').toString();

  for (const rule of BLOCK_REASON_PATTERNS) {
    const matched = rule.patterns.some(p => p.test(reason));
    if (!matched) continue;

    return {
      subtype:     rule.subtype,
      severity:    rule.severity,
      confidence:  rule.confidence,
      title:       `Signature failure: ${rule.tag} — requestId ${event.requestId ?? 'unknown'}`,
      description: `A signature verification failure was detected at the enforcement gateway. ` +
                   `reason="${reason}", subtype=${rule.subtype}. ` +
                   `This may indicate artifact tampering, key compromise, or a misconfigured client. ` +
                   `Full forensic context is preserved in the evidence payload.`,
      tags:        ['signature', rule.tag],
      evidence: {
        requestId:   event.requestId,
        artifactId:  event.artifactId,
        publicKeyId: event.publicKeyId,
        reason:      reason,
        tenantId:    event.tenantId,
        clientIp:    event.clientIp,
        rawEvent:    event.eventType,
      },
      context: {},
    };
  }

  return null;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Analyze a platform event for signature/cryptographic failures.
 *
 * @param {object} event  — Structured log record
 * @returns {{ triggered: boolean, alert?: object }}
 */
function analyze(event) {
  const eventName = event.eventType ?? '';

  // Direct rule match
  for (const rule of SIGNATURE_RULES) {
    if (!rule.events.includes(eventName)) continue;

    return {
      triggered: true,
      alert: {
        type:        ALERT_TYPE.SIGNATURE_FAILURE,
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
        publicKeyId: event.publicKeyId ?? event.keyId,
        clientIp:    event.clientIp,
        component:   event.component,
      },
    };
  }

  // Secondary: analyze GATEWAY_BLOCK by reason string
  if (eventName === 'GATEWAY_BLOCK') {
    const blockAlert = _analyzeBlockReason(event);
    if (blockAlert) {
      return {
        triggered: true,
        alert: {
          type:       ALERT_TYPE.SIGNATURE_FAILURE,
          sourceEvent: eventName,
          requestId:  event.requestId,
          artifactId: event.artifactId,
          tenantId:   event.tenantId,
          publicKeyId:event.publicKeyId,
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
