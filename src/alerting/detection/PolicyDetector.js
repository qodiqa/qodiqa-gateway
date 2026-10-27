'use strict';

/**
 * QODIQA Policy Failure Detector
 *
 * Monitors for all classes of policy enforcement failure:
 *   - Policy load/reload failures (gateway starts without valid policy)
 *   - Policy drift (policy set changed between signing and evaluation)
 *   - Execution invariant violations (code executed without valid artifact)
 *   - Rate limit store degradation (distributed rate limiting offline)
 *   - Fail-open detection (requests allowed through despite enforcement failure)
 *   - Policy bypass attempts (detected from audit analysis)
 *   - Configuration inconsistencies
 *
 * Policy failures in QODIQA are particularly critical because a fail-open
 * condition means AI outputs are executing without governance controls.
 */

const { ALERT_TYPE, POLICY_SUBTYPE, SEVERITY } = require('../constants');

// ── Direct-match policy failure rules ────────────────────────────────────────

const POLICY_RULES = [

  {
    events:    ['EXECUTION_INVARIANT_VIOLATED'],
    subtype:   POLICY_SUBTYPE.INVARIANT_VIOLATED,
    severity:  SEVERITY.CRITICAL,
    confidence: 100,
    title:     (ev) => `Execution invariant violated — code executed without verified artifact`,
    description: (ev) =>
      `The execution guard detected that provider code was called without a verified artifact. ` +
      `caller="${ev.caller ?? '?'}", requestId=${ev.requestId ?? '?'}. ` +
      `This is a CRITICAL security invariant violation — AI execution occurred outside ` +
      `the consent/policy enforcement chain. Immediate investigation required.`,
    tags:      ['policy', 'invariant', 'bypass', 'critical'],
    evidence:  (ev) => ({
      caller:     ev.caller,
      requestId:  ev.requestId,
      component:  ev.component,
      timestamp:  ev.timestamp,
    }),
    context:   () => ({ privilegedActor: true }),
  },

  {
    events:    ['POLICY_LOAD_FAILED'],
    subtype:   POLICY_SUBTYPE.LOAD_FAILURE,
    severity:  SEVERITY.CRITICAL,
    confidence: 100,
    title:     () => `Policy load failed — gateway starting without valid policy`,
    description: (ev) =>
      `The policy engine failed to load policies at startup. ` +
      `error="${ev.error ?? ev.reason ?? '?'}". ` +
      `Without valid policies, the gateway cannot make enforcement decisions. ` +
      `All requests will be blocked fail-closed until policies are restored.`,
    tags:      ['policy', 'load-failure', 'startup'],
    evidence:  (ev) => ({
      error:    ev.error ?? ev.reason,
      policyFile: ev.policyFile,
      timestamp:  ev.timestamp,
    }),
    context:   () => ({}),
  },

  {
    events:    ['POLICY_RELOAD_FAILED'],
    subtype:   POLICY_SUBTYPE.LOAD_FAILURE,
    severity:  SEVERITY.HIGH,
    confidence: 100,
    title:     () => `Policy reload failed — running with stale policy set`,
    description: (ev) =>
      `A live policy reload (SIGHUP) failed. ` +
      `error="${ev.error ?? ev.reason ?? '?'}". ` +
      `The gateway continues running with the previously loaded policy set, which may be outdated. ` +
      `Investigate and retry the reload.`,
    tags:      ['policy', 'reload-failure'],
    evidence:  (ev) => ({
      error:     ev.error ?? ev.reason,
      timestamp: ev.timestamp,
    }),
    context:   () => ({}),
  },

  {
    events:    ['POLICY_DRIFT_DETECTED'],
    subtype:   POLICY_SUBTYPE.DRIFT_DETECTED,
    severity:  SEVERITY.HIGH,
    confidence: 95,
    title:     (ev) => `Policy drift detected — artifact signed against different policy set`,
    description: (ev) =>
      `The policy hash embedded in the artifact does not match the current active policy set. ` +
      `Expected=${ev.expectedHash ?? '?'}, Got=${ev.actualHash ?? ev.policyHash ?? '?'}. ` +
      `requestId=${ev.requestId ?? '?'}. ` +
      `This indicates the policy set changed between when the artifact was signed and when ` +
      `it was submitted for enforcement. The request has been blocked.`,
    tags:      ['policy', 'drift', 'integrity'],
    evidence:  (ev) => ({
      requestId:    ev.requestId,
      expectedHash: ev.expectedHash,
      actualHash:   ev.actualHash ?? ev.policyHash,
      artifactId:   ev.artifactId,
      tenantId:     ev.tenantId,
    }),
    context:   () => ({}),
  },

  {
    events:    ['POLICY_RATE_LIMIT_EXCEEDED'],
    subtype:   POLICY_SUBTYPE.RATE_LIMIT_EXCEEDED,
    severity:  SEVERITY.MEDIUM,
    confidence: 100,
    title:     (ev) => `Rate limit exceeded — key ${ev.publicKeyId ?? 'unknown'}`,
    description: (ev) =>
      `The distributed rate limit policy was exceeded for key ${ev.publicKeyId ?? '?'}. ` +
      `count=${ev.count ?? '?'}, limit=${ev.limit ?? '?'}, window=${ev.window ?? '?'}. ` +
      `This may indicate an abusive client or automated attack. The request was blocked.`,
    tags:      ['policy', 'rate-limit'],
    evidence:  (ev) => ({
      publicKeyId: ev.publicKeyId,
      count:       ev.count,
      limit:       ev.limit,
      window:      ev.window,
      tenantId:    ev.tenantId,
      clientIp:    ev.clientIp,
    }),
    context:   () => ({}),
  },

  {
    events:    ['POLICY_RATE_LIMIT_DEGRADED'],
    subtype:   POLICY_SUBTYPE.ENFORCEMENT_FAILURE,
    severity:  SEVERITY.HIGH,
    confidence: 100,
    title:     () => `Rate limit store degraded — distributed rate limiting offline`,
    description: (ev) =>
      `The Redis-backed rate limit store is unavailable. ` +
      `source="${ev.source ?? '?'}". ` +
      `Distributed rate limiting is now operating in degraded mode. ` +
      `Requests are being blocked fail-closed until the store recovers.`,
    tags:      ['policy', 'enforcement', 'degraded'],
    evidence:  (ev) => ({
      source:  ev.source,
      message: ev.message,
    }),
    context:   () => ({}),
  },

];

// ── Block-reason policy sub-analysis ─────────────────────────────────────────

const POLICY_BLOCK_PATTERNS = [
  {
    patterns:  [/NO_EXPLICIT_ALLOW/i, /NO_POLICIES/i, /INVALID_POLICY/i],
    subtype:   POLICY_SUBTYPE.EVALUATION_FAILURE,
    severity:  SEVERITY.HIGH,
    confidence: 90,
    tag:       'no-allow-policy',
  },
  {
    patterns:  [/BYPASS/i, /skip.*policy/i, /policy.*skip/i],
    subtype:   POLICY_SUBTYPE.BYPASS_ATTEMPT,
    severity:  SEVERITY.CRITICAL,
    confidence: 85,
    tag:       'bypass-attempt',
  },
  {
    patterns:  [/NO_CONSENT/i, /CONSENT_DENIED/i, /CONSENT_REVOKED/i],
    subtype:   POLICY_SUBTYPE.EVALUATION_FAILURE,
    severity:  SEVERITY.MEDIUM,
    confidence: 95,
    tag:       'consent-failure',
  },
  {
    patterns:  [/INVALID_CONTEXT/i, /MISSING_FIELD/i],
    subtype:   POLICY_SUBTYPE.CONFIG_INCONSISTENCY,
    severity:  SEVERITY.MEDIUM,
    confidence: 80,
    tag:       'context-invalid',
  },
];

function _analyzeBlockReason(event) {
  const reason = (event.reason ?? '').toString();

  for (const rule of POLICY_BLOCK_PATTERNS) {
    const matched = rule.patterns.some(p => p.test(reason));
    if (!matched) continue;

    return {
      subtype:     rule.subtype,
      severity:    rule.severity,
      confidence:  rule.confidence,
      title:       `Policy enforcement failure: ${rule.tag} — requestId ${event.requestId ?? 'unknown'}`,
      description: `A policy enforcement failure was detected at the gateway. ` +
                   `reason="${reason}", pattern=${rule.tag}. ` +
                   `requestId=${event.requestId ?? '?'}, artifactId=${event.artifactId ?? '?'}. ` +
                   `The request was blocked. Review the policy configuration and context.`,
      tags:        ['policy', rule.tag],
      evidence: {
        requestId:  event.requestId,
        artifactId: event.artifactId,
        reason:     reason,
        tenantId:   event.tenantId,
        clientIp:   event.clientIp,
      },
      context: {},
    };
  }

  return null;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Analyze a platform event for policy enforcement failures.
 *
 * @param {object} event  — Structured log record
 * @returns {{ triggered: boolean, alert?: object }}
 */
function analyze(event) {
  const eventName = event.eventType ?? '';

  // Direct rule match
  for (const rule of POLICY_RULES) {
    if (!rule.events.includes(eventName)) continue;

    return {
      triggered: true,
      alert: {
        type:        ALERT_TYPE.POLICY_FAILURE,
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

  // Secondary analysis via GATEWAY_BLOCK reason
  if (eventName === 'GATEWAY_BLOCK') {
    const blockAlert = _analyzeBlockReason(event);
    if (blockAlert) {
      return {
        triggered: true,
        alert: {
          type:       ALERT_TYPE.POLICY_FAILURE,
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
