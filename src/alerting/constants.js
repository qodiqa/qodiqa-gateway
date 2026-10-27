'use strict';

/**
 * QODIQA Alerting & Notification Framework — Canonical Constants
 *
 * Single source of truth for all alert types, severities, channels,
 * status values, and escalation definitions used across the framework.
 */

// ── Alert Types ───────────────────────────────────────────────────────────────

const ALERT_TYPE = Object.freeze({
  REPLAY_ATTACK:     'REPLAY_ATTACK',
  SIGNATURE_FAILURE: 'SIGNATURE_FAILURE',
  POLICY_FAILURE:    'POLICY_FAILURE',
  ANOMALY:           'ANOMALY',
  OPERATIONAL:       'OPERATIONAL',
  GOVERNANCE:        'GOVERNANCE',
});

// ── Alert Subtypes ────────────────────────────────────────────────────────────

const REPLAY_SUBTYPE = Object.freeze({
  NONCE_REUSE:                'NONCE_REUSE',
  DUPLICATE_ARTIFACT:         'DUPLICATE_ARTIFACT',
  REPEATED_REQUEST_HASH:      'REPEATED_REQUEST_HASH',
  CROSS_TENANT_REPLAY:        'CROSS_TENANT_REPLAY',
  EXPIRED_ARTIFACT:           'EXPIRED_ARTIFACT',
  EXCESSIVE_RETRY:            'EXCESSIVE_RETRY',
  REQUEST_BINDING_MISMATCH:   'REQUEST_BINDING_MISMATCH',
  ANOMALY_THRESHOLD:          'ANOMALY_THRESHOLD',
});

const SIGNATURE_SUBTYPE = Object.freeze({
  INVALID_SIGNATURE:          'INVALID_SIGNATURE',
  MISSING_SIGNATURE:          'MISSING_SIGNATURE',
  CORRUPTED_SIGNATURE:        'CORRUPTED_SIGNATURE',
  VERIFICATION_FAILURE:       'VERIFICATION_FAILURE',
  KEY_MISMATCH:               'KEY_MISMATCH',
  UNKNOWN_KEY:                'UNKNOWN_KEY',
  EXPIRED_KEY:                'EXPIRED_KEY',
  REVOKED_KEY:                'REVOKED_KEY',
  MALFORMED_ARTIFACT:         'MALFORMED_ARTIFACT',
  ENVELOPE_BINDING_FAILURE:   'ENVELOPE_BINDING_FAILURE',
  MULTIPLE_ACTIVE_KEYS:       'MULTIPLE_ACTIVE_KEYS',
});

const POLICY_SUBTYPE = Object.freeze({
  EVALUATION_FAILURE:         'EVALUATION_FAILURE',
  EXECUTION_FAILURE:          'EXECUTION_FAILURE',
  MISSING_POLICY:             'MISSING_POLICY',
  BYPASS_ATTEMPT:             'BYPASS_ATTEMPT',
  ENFORCEMENT_FAILURE:        'ENFORCEMENT_FAILURE',
  FAIL_OPEN_DETECTED:         'FAIL_OPEN_DETECTED',
  CONFIG_INCONSISTENCY:       'CONFIG_INCONSISTENCY',
  DRIFT_DETECTED:             'DRIFT_DETECTED',
  RATE_LIMIT_EXCEEDED:        'RATE_LIMIT_EXCEEDED',
  INVARIANT_VIOLATED:         'INVARIANT_VIOLATED',
  LOAD_FAILURE:               'LOAD_FAILURE',
});

const ANOMALY_SUBTYPE = Object.freeze({
  VOLUME_SPIKE:               'VOLUME_SPIKE',
  TRAFFIC_SPIKE:              'TRAFFIC_SPIKE',
  GEOGRAPHIC_ANOMALY:         'GEOGRAPHIC_ANOMALY',
  TENANT_ANOMALY:             'TENANT_ANOMALY',
  ENFORCEMENT_ANOMALY:        'ENFORCEMENT_ANOMALY',
  AUDIT_ACTIVITY_ANOMALY:     'AUDIT_ACTIVITY_ANOMALY',
  KEY_USAGE_ANOMALY:          'KEY_USAGE_ANOMALY',
  GOVERNANCE_ANOMALY:         'GOVERNANCE_ANOMALY',
  BLOCK_RATE_SPIKE:           'BLOCK_RATE_SPIKE',
  ERROR_RATE_SPIKE:           'ERROR_RATE_SPIKE',
  BURST_DETECTION:            'BURST_DETECTION',
  BASELINE_DEVIATION:         'BASELINE_DEVIATION',
});

const OPERATIONAL_SUBTYPE = Object.freeze({
  REDIS_DEGRADED:                  'REDIS_DEGRADED',
  PG_DEGRADED:                     'PG_DEGRADED',
  NONCE_STORE_DEGRADED:            'NONCE_STORE_DEGRADED',
  ANOMALY_STORE_DEGRADED:          'ANOMALY_STORE_DEGRADED',
  RATE_LIMIT_DEGRADED:             'RATE_LIMIT_DEGRADED',
  PROVIDER_FAILURE:                'PROVIDER_FAILURE',
  AUDIT_CHAIN_CORRUPTED:           'AUDIT_CHAIN_CORRUPTED',
  // Live Audit Chain Integrity Verifier — CHAIN-2. Distinct from
  // AUDIT_CHAIN_CORRUPTED: structural findings (e.g. a bare PG sequence
  // gap) that may be a benign persistence artifact rather than tampering —
  // see src/core/audit/verifier/diagnostics.js's severity split.
  AUDIT_CHAIN_STRUCTURAL_ANOMALY:  'AUDIT_CHAIN_STRUCTURAL_ANOMALY',
  // S4 (OD-5): the derived audit_chain row counter disagrees with count(*) (src/core/audit/mirrorCountReconciler.js)
  AUDIT_MIRROR_COUNT_DRIFT:        'AUDIT_MIRROR_COUNT_DRIFT',
  STARTUP_FAILURE:                 'STARTUP_FAILURE',
  PERSISTENCE_UNSAFE:              'PERSISTENCE_UNSAFE',
  FLAPPING_DETECTED:               'FLAPPING_DETECTED',
  // Signing/KMS resilience layer (src/infra/keys/resilience/) — MON-3
  SIGNING_DEGRADED:                'SIGNING_DEGRADED',
  // Redis HA mode (src/infra/redis/managedClient.js) — MON-3
  REDIS_HA_MISCONFIGURED:          'REDIS_HA_MISCONFIGURED',
  // Transparency Gap Handling — Component #14
  TRANSPARENCY_GAP:                'TRANSPARENCY_GAP',
  TRANSPARENCY_HASH_CHAIN_BREAK:   'TRANSPARENCY_HASH_CHAIN_BREAK',
  TRANSPARENCY_CHECKPOINT_DIVERGE: 'TRANSPARENCY_CHECKPOINT_DIVERGE',
  // #9 — complete alert coverage
  LATENCY_SLA_BREACH:              'LATENCY_SLA_BREACH',
  LATENCY_P99_BREACH:              'LATENCY_P99_BREACH',
  AUDIT_DISK_FULL:                 'AUDIT_DISK_FULL',
  // Advance-warning subtypes — distinct from SIGNATURE_SUBTYPE.EXPIRED_KEY
  // (KEY_EXPIRED/TENANT_KEY_EXPIRED_ACTIVE), which are already-expired.
  KEY_EXPIRY_APPROACHING:          'KEY_EXPIRY_APPROACHING',
  KEY_ROTATION_OVERDUE:            'KEY_ROTATION_OVERDUE',
  PG_POOL_EXHAUSTED:               'PG_POOL_EXHAUSTED',
  // consent revocation/suspension propagation to other nodes failed
  CONSENT_PROPAGATION_FAILED:      'CONSENT_PROPAGATION_FAILED',
  // a persistence/transparency queue crossed its depth alert threshold
  // (src/core/persistenceRecovery/queueMonitor.js)
  QUEUE_BACKLOG:                   'QUEUE_BACKLOG',
});

const GOVERNANCE_SUBTYPE = Object.freeze({
  RBAC_VIOLATION:             'RBAC_VIOLATION',
  UNAUTHORIZED_KEY_ADMIN:     'UNAUTHORIZED_KEY_ADMIN',
  OPS_AUTH_FAILURE:           'OPS_AUTH_FAILURE',
  COMPLIANCE_EXPORT_FAILED:   'COMPLIANCE_EXPORT_FAILED',
  AUDIT_ACCESS_DENIED:        'AUDIT_ACCESS_DENIED',
  // file-based policy store vs. Postgres governance ledger divergence
  RECONCILIATION_DIVERGENCE:  'RECONCILIATION_DIVERGENCE',
  // sensitive data that LEFT through an answer or a tool result without being redacted or blocked (a DLP rule in DETECT mode, or an exfiltration signal)
  DATA_EXPOSURE:              'DATA_EXPOSURE',
});

// ── Severity Levels ───────────────────────────────────────────────────────────

const SEVERITY = Object.freeze({
  INFO:     'INFO',
  LOW:      'LOW',
  MEDIUM:   'MEDIUM',
  HIGH:     'HIGH',
  CRITICAL: 'CRITICAL',
});

// Numeric weights for scoring and comparison
const SEVERITY_WEIGHT = Object.freeze({
  INFO:     1,
  LOW:      2,
  MEDIUM:   3,
  HIGH:     4,
  CRITICAL: 5,
});

// ── Alert Status ──────────────────────────────────────────────────────────────

const ALERT_STATUS = Object.freeze({
  OPEN:          'OPEN',
  ACKNOWLEDGED:  'ACKNOWLEDGED',
  INVESTIGATING: 'INVESTIGATING',
  RESOLVED:      'RESOLVED',
  SUPPRESSED:    'SUPPRESSED',
  CLOSED:        'CLOSED',
  FALSE_POSITIVE:'FALSE_POSITIVE',
});

// ── Notification Channels ─────────────────────────────────────────────────────

const CHANNEL = Object.freeze({
  EMAIL:      'EMAIL',
  WEBHOOK:    'WEBHOOK',
  SLACK:      'SLACK',
  TEAMS:      'TEAMS',
  SIEM:       'SIEM',
  PAGERDUTY:  'PAGERDUTY',
  SMS:        'SMS',
});

// ── Escalation Levels ─────────────────────────────────────────────────────────

const ESCALATION_LEVEL = Object.freeze({
  L0: 0,  // Initial alert — logged only (INFO)
  L1: 1,  // Notify primary on-call
  L2: 2,  // Notify security team
  L3: 3,  // Notify compliance + management
  L4: 4,  // Notify CISO + executive escalation
});

// ── Severity → Default Escalation Path ───────────────────────────────────────

const SEVERITY_ESCALATION = Object.freeze({
  INFO:     { startLevel: ESCALATION_LEVEL.L0, maxLevel: ESCALATION_LEVEL.L0, ackWindowMs: null },
  LOW:      { startLevel: ESCALATION_LEVEL.L1, maxLevel: ESCALATION_LEVEL.L1, ackWindowMs: 4 * 3600_000 },
  MEDIUM:   { startLevel: ESCALATION_LEVEL.L1, maxLevel: ESCALATION_LEVEL.L2, ackWindowMs: 2 * 3600_000 },
  HIGH:     { startLevel: ESCALATION_LEVEL.L2, maxLevel: ESCALATION_LEVEL.L3, ackWindowMs: 30 * 60_000 },
  CRITICAL: { startLevel: ESCALATION_LEVEL.L3, maxLevel: ESCALATION_LEVEL.L4, ackWindowMs: 15 * 60_000 },
});

// ── Correlation Window Defaults ───────────────────────────────────────────────

const CORRELATION = Object.freeze({
  DEFAULT_WINDOW_MS:     5 * 60_000,   // 5 minutes
  INCIDENT_WINDOW_MS:   15 * 60_000,   // 15 minutes
  MAX_ALERTS_PER_INCIDENT: 500,
  MIN_ALERTS_FOR_INCIDENT: 2,
  FLAP_THRESHOLD:        5,            // same event N times in window = flapping
  SUPPRESSION_WINDOW_MS: 60_000,       // deduplicate identical alerts within 1 min
});

// ── Retention Defaults ────────────────────────────────────────────────────────

const RETENTION = Object.freeze({
  INFO_DAYS:     30,
  LOW_DAYS:      90,
  MEDIUM_DAYS:  180,
  HIGH_DAYS:    365,
  CRITICAL_DAYS: 730,  // 2 years — meets most compliance requirements
});

// ── Risk Score Ranges ─────────────────────────────────────────────────────────

const RISK_SCORE = Object.freeze({
  MIN: 0,
  MAX: 100,
  THRESHOLDS: {
    INFO:     { min: 0,  max: 19  },
    LOW:      { min: 20, max: 39  },
    MEDIUM:   { min: 40, max: 59  },
    HIGH:     { min: 60, max: 79  },
    CRITICAL: { min: 80, max: 100 },
  },
});

module.exports = {
  ALERT_TYPE,
  REPLAY_SUBTYPE,
  SIGNATURE_SUBTYPE,
  POLICY_SUBTYPE,
  ANOMALY_SUBTYPE,
  OPERATIONAL_SUBTYPE,
  GOVERNANCE_SUBTYPE,
  SEVERITY,
  SEVERITY_WEIGHT,
  ALERT_STATUS,
  CHANNEL,
  ESCALATION_LEVEL,
  SEVERITY_ESCALATION,
  CORRELATION,
  RETENTION,
  RISK_SCORE,
};
