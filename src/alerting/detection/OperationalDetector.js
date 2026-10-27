'use strict';

/**
 * QODIQA Operational & Governance Detector
 *
 * Detects infrastructure degradation, governance violations, and
 * audit chain integrity failures.
 */

const { ALERT_TYPE, OPERATIONAL_SUBTYPE, GOVERNANCE_SUBTYPE, SEVERITY } = require('../constants');

const OPERATIONAL_RULES = [

  {
    events:   ['REPLAY_PROTECTION_DEGRADED', 'GATEWAY_RUNTIME_DEGRADED'],
    // RC-10: server/startup.js also emits REPLAY_PROTECTION_DEGRADED with
    // source "PERSISTENCE" when the nonce store is UP but Redis AOF is not durable. That is
    // not "store unavailable / all execution blocked" — it is already alerted (HIGH) via the
    // REDIS_PERSISTENCE_UNSAFE event emitted in the same branch. Paging it as this CRITICAL
    // P1 produced a false, never-resolving incident during the RC soak.
    matches:  (ev) => ev.source !== 'PERSISTENCE',
    subtype:  OPERATIONAL_SUBTYPE.REDIS_DEGRADED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    () => `Replay protection degraded — Redis nonce store unavailable`,
    description: (ev) =>
      `The Redis nonce store is unavailable. Replay protection is offline. ` +
      `source="${ev.source ?? '?'}". All execution requests are being blocked fail-closed ` +
      `until the store recovers. This is a P1 operational incident.`,
    tags:     ['operational', 'redis', 'replay-protection'],
    evidence: (ev) => ({ source: ev.source, message: ev.message }),
  },

  {
    events:   ['GATEWAY_RUNTIME_PARTIAL_FAILURE'],
    subtype:  OPERATIONAL_SUBTYPE.REDIS_DEGRADED,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    () => `Gateway runtime partially degraded — one or more Redis stores offline`,
    description: (ev) =>
      `One or more Redis stores have failed. Partial protection is active. ` +
      `nonce=${ev.nonceStoreReady}, anomaly=${ev.anomalyStoreReady}, rl=${ev.rateLimitStoreReady}. ` +
      `Affected execution paths are blocked fail-closed.`,
    tags:     ['operational', 'redis', 'partial-failure'],
    evidence: (ev) => ({
      nonceReady:   ev.nonceStoreReady,
      anomalyReady: ev.anomalyStoreReady,
      rlReady:      ev.rateLimitStoreReady,
    }),
  },

  {
    events:   ['AUDIT_CHAIN_CORRUPTED'],
    subtype:  OPERATIONAL_SUBTYPE.AUDIT_CHAIN_CORRUPTED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    () => `Audit chain integrity corrupted — immutable log tampered`,
    description: (ev) =>
      `The audit chain hash linkage has been broken. This indicates unauthorized modification ` +
      `of the audit log, disk corruption, or an attack on audit integrity. ` +
      `reason="${ev.reason ?? '?'}". Immediate forensic investigation required. ` +
      `DO NOT allow further writes until the chain is validated.`,
    tags:     ['operational', 'audit', 'integrity', 'critical'],
    evidence: (ev) => ({
      reason:        ev.reason,
      expectedHash:  ev.expectedHash,
      actualHash:    ev.actualHash,
      entryIndex:    ev.entryIndex,
    }),
  },

  {
    // Live Audit Chain Integrity Verifier (CHAIN-2) — structural findings
    // that are NOT necessarily tampering, unlike AUDIT_CHAIN_CORRUPTED above.
    // Currently only SEQUENCE_GAP routes here: audit_chain.seq is BIGSERIAL
    // with no uniqueness constraint, and PostgreSQL's nextval() is
    // non-transactional, so a rolled-back insert permanently burns a
    // sequence value — a gap can be routine background noise, not an
    // integrity breach. See src/core/audit/verifier/diagnostics.js.
    events:   ['AUDIT_CHAIN_STRUCTURAL_ANOMALY'],
    subtype:  OPERATIONAL_SUBTYPE.AUDIT_CHAIN_STRUCTURAL_ANOMALY,
    severity: SEVERITY.MEDIUM,
    confidence: 70,
    title:    (ev) => `Audit chain structural anomaly detected — ${ev.reason ?? 'unknown reason'}`,
    description: (ev) =>
      `The live audit chain verifier found a structural anomaly (reason="${ev.reason ?? '?'}") that may indicate ` +
      `a transient persistence issue rather than tampering — investigate before escalating. Unlike a broken hash ` +
      `chain, this finding alone does not block further writes.`,
    tags:     ['operational', 'audit', 'integrity', 'structural'],
    evidence: (ev) => ({
      reason:      ev.reason,
      trigger:     ev.trigger,
      previousSeq: ev.previousSeq,
      actualSeq:   ev.actualSeq,
      expectedSeq: ev.expectedSeq,
    }),
  },

  {
    // S4 (OD-5): the derived audit_chain row counter (migration 073, read by the 60 s PG lag monitor) does not
    // equal count(*), or its row is missing. Only a write that bypassed audit_chain's triggers (table owner / superuser)
    // can cause this. Never repaired automatically: the owner rebuild is the recovery. Re-raised on every reconcile
    // run while it persists (consecutiveDriftRuns). See src/core/audit/mirrorCountReconciler.js.
    events:   ['AUDIT_MIRROR_COUNT_DRIFT'],
    subtype:  OPERATIONAL_SUBTYPE.AUDIT_MIRROR_COUNT_DRIFT,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Audit chain mirror counter drift — ${ev.reason ?? 'MISMATCH'}`,
    description: (ev) =>
      `The audit_chain row counter (stored=${ev.stored ?? 'missing'}) does not equal count(*) (exact=${ev.exact ?? '?'}) ` +
      `on reconcile trigger="${ev.trigger ?? '?'}" (run ${ev.consecutiveDriftRuns ?? 1} in a row). The counter is only changed by ` +
      `audit_chain's own triggers, so audit_chain was modified with its triggers bypassed (table owner or superuser). ` +
      `Investigate that change; the counter is NOT repaired automatically — after investigation the owner runs ` +
      `the owner-only counter rebuild (migration 073). Until then the PG lag value is wrong.`,
    tags:     ['operational', 'audit', 'integrity', 'mirror-counter'],
    evidence: (ev) => ({
      reason:               ev.reason,
      trigger:              ev.trigger,
      stored:               ev.stored,
      exact:                ev.exact,
      delta:                ev.delta,
      consecutiveDriftRuns: ev.consecutiveDriftRuns,
      firstDetectedAt:      ev.firstDetectedAt,
    }),
  },

  {
    events:   ['REDIS_PERSISTENCE_UNSAFE'],
    subtype:  OPERATIONAL_SUBTYPE.PERSISTENCE_UNSAFE,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    () => `Redis persistence not durably configured — replay protection at risk`,
    description: (ev) =>
      `Redis AOF persistence is disabled or not configured to 'everysec'. ` +
      `aofEnabled=${ev.aofEnabled}, appendfsync="${ev.appendfsync}". ` +
      `A Redis restart or crash could cause nonce state loss, allowing replayed requests ` +
      `to bypass replay protection.`,
    tags:     ['operational', 'redis', 'persistence'],
    evidence: (ev) => ({
      aofEnabled:  ev.aofEnabled,
      appendfsync: ev.appendfsync,
      warnings:    ev.warningCount,
    }),
  },

  {
    // #1 (finding #108): src/infra/redis/persistenceMonitor.js's
    // background check, distinct from REDIS_PERSISTENCE_UNSAFE above (which
    // is startup-only) — this fires when persistence was safe at some point
    // during this process's lifetime and has since drifted to unsafe.
    events:   ['REDIS_PERSISTENCE_DRIFT_DETECTED'],
    subtype:  OPERATIONAL_SUBTYPE.PERSISTENCE_UNSAFE,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    () => `Redis persistence configuration drifted to unsafe after startup`,
    description: (ev) =>
      `Redis persistence was confirmed safe at some point during this process's runtime and has ` +
      `since drifted to an unsafe configuration. aofEnabled=${ev.aofEnabled}, appendfsync="${ev.appendfsync}". ` +
      `A Redis restart or crash could now cause nonce state loss, allowing replayed requests ` +
      `to bypass replay protection. This indicates unmanaged runtime configuration change, not a ` +
      `misconfiguration present since boot.`,
    tags:     ['operational', 'redis', 'persistence', 'drift'],
    evidence: (ev) => ({
      fromState:   ev.fromState,
      toState:     ev.toState,
      aofEnabled:  ev.aofEnabled,
      appendfsync: ev.appendfsync,
      warnings:    ev.warnings,
    }),
  },

  {
    events:   ['REDIS_RECONNECT_FLAPPING'],
    subtype:  OPERATIONAL_SUBTYPE.FLAPPING_DETECTED,
    severity: SEVERITY.HIGH,
    confidence: 90,
    title:    () => `Redis connection flapping — repeated connect/disconnect cycles`,
    description: (ev) =>
      `Redis is experiencing repeated reconnection cycles. This causes intermittent ` +
      `availability of replay protection and rate limiting. ` +
      `reconnects=${ev.reconnects ?? '?'}, store="${ev.store ?? '?'}". ` +
      `Investigate Redis connectivity and network stability.`,
    tags:     ['operational', 'redis', 'flapping'],
    evidence: (ev) => ({ reconnects: ev.reconnects, store: ev.store }),
  },

  {
    events:   ['PG_AUDIT_PERSIST_FAILED'],
    subtype:  OPERATIONAL_SUBTYPE.PG_DEGRADED,
    severity: SEVERITY.MEDIUM,
    confidence: 100,
    title:    () => `PostgreSQL audit persistence failed`,
    description: (ev) =>
      `An audit event failed to persist to PostgreSQL. ` +
      `error="${ev.error ?? '?'}". The file-based audit chain is unaffected, ` +
      `but centralized search and compliance reports may be incomplete.`,
    tags:     ['operational', 'postgres', 'audit'],
    evidence: (ev) => ({ error: ev.error, eventType: ev.eventType }),
  },

  // ── B3: evidence-chain / audit-chain PG persistence gaps (findings f997bb6,
  // 4b27e02) — both already logged (services/logger.js) + metriced
  // (evidenceChainPersistFailuresTotal / auditPgHydrationFailedTotal in
  // observability/metrics.js) but never reached the alerting pipeline.
  // Fire-on-first-occurrence, matching PG_AUDIT_PERSIST_FAILED above (this
  // file's unanimous convention — no rule here uses a window/threshold).

  {
    events:   ['EVIDENCE_CHAIN_PERSIST_FAILED'],
    subtype:  OPERATIONAL_SUBTYPE.PG_DEGRADED,
    severity: SEVERITY.MEDIUM,
    confidence: 100,
    title:    () => `Evidence chain record persistence failed`,
    description: (ev) =>
      `An evidence chain record failed to persist to PostgreSQL for artifact "${ev.artifactId ?? '?'}". ` +
      `error="${ev.error ?? '?'}" code="${ev.code ?? '?'}". The audit log entry itself is unaffected — ` +
      `only the evidence-chain mirror is missing this record, which may impact compliance/evidence ` +
      `export completeness.`,
    tags:     ['operational', 'postgres', 'evidence-chain'],
    evidence: (ev) => ({ artifactId: ev.artifactId, error: ev.error, code: ev.code }),
  },

  {
    events:   ['AUDIT_PG_HYDRATION_FAILED'],
    subtype:  OPERATIONAL_SUBTYPE.PG_DEGRADED,
    severity: SEVERITY.MEDIUM,
    confidence: 100,
    title:    () => `Audit-chain PG tail hydration failed — fell back to GENESIS`,
    description: (ev) =>
      `Single-node startup hydration of the audit-chain tail hash from PostgreSQL failed ` +
      `(error="${ev.error ?? '?'}" code="${ev.code ?? '?'}"), falling back to GENESIS/file state. ` +
      `On a database that already holds committed history, this risks a prevHash collision on the ` +
      `next append (see FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION-REPORT.md) — verify audit_chain ` +
      `state before further writes.`,
    tags:     ['operational', 'postgres', 'audit', 'audit-chain'],
    evidence: (ev) => ({ error: ev.error, code: ev.code }),
  },

  // ── Transparency sign-only degradation ────────────────────────────────
  // registrar.js's non-PG branch signs but doesn't persist; aiChat.js now
  // checks persisted:false and emits this event instead of staying silent.

  {
    events:   ['TRANSPARENCY_PERSISTENCE_DEGRADED'],
    subtype:  OPERATIONAL_SUBTYPE.TRANSPARENCY_GAP,
    severity: SEVERITY.MEDIUM,
    confidence: 100,
    title:    () => `Transparency entry signed but not durably persisted`,
    description: (ev) =>
      `A transparency log entry for request "${ev.requestId ?? '?'}" was signed but not persisted to ` +
      `PostgreSQL (Postgres disabled). The signed entry exists but carries no durable, externally-` +
      `verifiable Merkle evidence — a post-incident investigation cannot rely on this decision's ` +
      `transparency record surviving a restart.`,
    tags:     ['operational', 'transparency', 'postgres'],
    evidence: (ev) => ({ requestId: ev.requestId, transparencyId: ev.transparencyId, tenantId: ev.tenantId }),
  },

  // ── Signing/KMS resilience (src/infra/keys/resilience/) — MON-3 ───────────
  // Previously logged + metriced only (qodiqa_signing_* in metrics.js) with
  // no matching alert rule — a KMS/HSM outage produced no notification
  // regardless of channel configuration.

  {
    events:   ['SIGNING_PROVIDER_INIT_FAILED'],
    subtype:  OPERATIONAL_SUBTYPE.SIGNING_DEGRADED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Signing provider failed to initialize — ${ev.provider ?? 'unknown provider'}`,
    description: (ev) =>
      `The signing/KMS provider "${ev.provider ?? '?'}" failed to initialize. ` +
      `error="${ev.error ?? '?'}". Signing operations relying on this provider will fail ` +
      `until it is restored. Verify KMS/HSM connectivity and credentials.`,
    tags:     ['operational', 'signing', 'kms', 'critical'],
    evidence: (ev) => ({ provider: ev.provider, error: ev.error, elapsedMs: ev.elapsedMs }),
  },

  {
    events:   ['SIGNING_HEALTH_DEGRADED'],
    subtype:  OPERATIONAL_SUBTYPE.SIGNING_DEGRADED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Signing provider health degraded — ${ev.provider ?? 'unknown provider'} (${ev.from ?? '?'} -> ${ev.to ?? '?'})`,
    description: (ev) =>
      `Signing provider "${ev.provider ?? '?'}" health transitioned from "${ev.from ?? '?'}" to ` +
      `"${ev.to ?? '?'}" (reason="${ev.reason ?? '?'}"). consecutiveFailures=${ev.consecutiveFailures ?? '?'}. ` +
      `Signing capacity may be reduced or unavailable until the provider recovers.`,
    tags:     ['operational', 'signing', 'kms', 'critical'],
    evidence: (ev) => ({
      provider: ev.provider, from: ev.from, to: ev.to,
      reason: ev.reason, consecutiveFailures: ev.consecutiveFailures, lastError: ev.lastError,
    }),
  },

  {
    events:   ['SIGNING_RETRY_EXHAUSTED'],
    subtype:  OPERATIONAL_SUBTYPE.SIGNING_DEGRADED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Signing operation retries exhausted — ${ev.provider ?? 'unknown provider'}`,
    description: (ev) =>
      `Signing operation "${ev.operation ?? '?'}" on provider "${ev.provider ?? '?'}" exhausted ` +
      `all ${ev.attempts ?? '?'} retry attempts (category="${ev.category ?? '?'}"). ` +
      `error="${ev.error ?? '?'}". Requests depending on this operation are failing.`,
    tags:     ['operational', 'signing', 'kms', 'critical'],
    evidence: (ev) => ({
      provider: ev.provider, operation: ev.operation, attempts: ev.attempts,
      category: ev.category, error: ev.error,
    }),
  },

  // ── Redis HA mode (src/infra/redis/managedClient.js) — MON-3 ──────────────
  // These are the newer sentinel/cluster HA-mode events, distinct from the
  // older single-client REDIS_RECONNECT_FLAPPING/REDIS_PERSISTENCE_UNSAFE
  // rules above. Previously logged + metriced only.

  {
    events:   ['REDIS_HA_CONNECTION_LOST'],
    subtype:  OPERATIONAL_SUBTYPE.REDIS_DEGRADED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Redis HA connection lost — ${ev.purpose ?? 'unknown purpose'}`,
    description: (ev) =>
      `The Redis connection for "${ev.purpose ?? '?'}" (mode="${ev.mode ?? '?'}") was lost. ` +
      `error="${ev.error ?? '?'}". Dependent functionality is degraded or unavailable ` +
      `until the connection recovers.`,
    tags:     ['operational', 'redis', 'ha', 'critical'],
    evidence: (ev) => ({ purpose: ev.purpose, mode: ev.mode, error: ev.error }),
  },

  {
    events:   ['REDIS_HA_RECONNECT_EXHAUSTED_FOR_NODE'],
    subtype:  OPERATIONAL_SUBTYPE.REDIS_DEGRADED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Redis HA node unreachable — reconnect attempts exhausted (${ev.purpose ?? 'unknown purpose'})`,
    description: (ev) =>
      `Redis node for "${ev.purpose ?? '?'}" (mode="${ev.mode ?? '?'}") exhausted ${ev.retries ?? '?'} ` +
      `reconnect attempts and is being treated as unreachable. ${ev.note ?? ''}`,
    tags:     ['operational', 'redis', 'ha', 'critical'],
    evidence: (ev) => ({ purpose: ev.purpose, mode: ev.mode, retries: ev.retries }),
  },

  {
    events:   ['REDIS_HA_CONFIG_INVALID'],
    subtype:  OPERATIONAL_SUBTYPE.REDIS_HA_MISCONFIGURED,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    (ev) => `Redis HA configuration invalid — ${ev.purpose ?? 'unknown purpose'}`,
    description: (ev) =>
      `Redis HA configuration for "${ev.purpose ?? '?'}" failed validation: ` +
      `${Array.isArray(ev.errors) ? ev.errors.join('; ') : (ev.errors ?? '?')}. ` +
      `This is a deployment misconfiguration, not necessarily an active outage — correct it ` +
      `before the next restart or failover event.`,
    tags:     ['operational', 'redis', 'ha', 'configuration'],
    evidence: (ev) => ({ purpose: ev.purpose, errors: ev.errors }),
  },

  // ── #9: complete alert coverage ──────────────────────────────────

  {
    events:   ['REQUEST_LATENCY_SLA_BREACH'],
    subtype:  OPERATIONAL_SUBTYPE.LATENCY_SLA_BREACH,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    () => `Request latency SLA breached`,
    description: (ev) =>
      `Mean request latency (${ev.meanMs ?? '?'}ms) has exceeded the configured SLA threshold ` +
      `(${ev.slaThresholdMs ?? '?'}ms). Investigate provider latency, event-loop delay, and Redis/PG ` +
      `round-trip times.`,
    tags:     ['operational', 'latency', 'sla'],
    evidence: (ev) => ({ meanMs: ev.meanMs, slaThresholdMs: ev.slaThresholdMs }),
  },

  {
    events:   ['REQUEST_LATENCY_P99_BREACH'],
    subtype:  OPERATIONAL_SUBTYPE.LATENCY_P99_BREACH,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    () => `Request latency p99 breached`,
    description: (ev) =>
      `p99 request latency (${ev.p99Ms ?? '?'}ms) has exceeded the configured threshold ` +
      `(${ev.p99ThresholdMs ?? '?'}ms) — a meaningful minority of requests are experiencing severe ` +
      `latency even if the mean looks healthy.`,
    tags:     ['operational', 'latency', 'p99'],
    evidence: (ev) => ({ p99Ms: ev.p99Ms, p99ThresholdMs: ev.p99ThresholdMs }),
  },

  {
    events:   ['AUDIT_DISK_FULL'],
    subtype:  OPERATIONAL_SUBTYPE.AUDIT_DISK_FULL,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    () => `Audit log disk full — evidence persistence at risk`,
    description: (ev) =>
      `The audit log append path exhausted its retry budget with ENOSPC (disk full). ` +
      `stage="${ev.stage ?? '?'}". QODIQA fails closed rather than serve a decision it cannot ` +
      `durably evidence — free disk space immediately.`,
    tags:     ['operational', 'audit', 'disk', 'critical'],
    evidence: (ev) => ({ stage: ev.stage, attempts: ev.attempts }),
  },

  {
    // Advance warning, distinct from KEY_EXPIRED/TENANT_KEY_EXPIRED_ACTIVE
    // (SignatureDetector.js), which fire once a key is already expired.
    events:   ['KEY_EXPIRING_SOON'],
    subtype:  OPERATIONAL_SUBTYPE.KEY_EXPIRY_APPROACHING,
    severity: SEVERITY.LOW,
    confidence: 100,
    title:    (ev) => `Signing key expiring soon — ${ev.daysRemaining ?? '?'} day(s) remaining`,
    description: (ev) =>
      `Active signing key "${ev.keyId ?? '?'}" for client "${ev.clientId ?? '?'}" expires in ` +
      `${ev.daysRemaining ?? '?'} day(s). Rotate before expiry to avoid a signing outage.`,
    tags:     ['operational', 'keys', 'expiry'],
    evidence: (ev) => ({ clientId: ev.clientId, keyId: ev.keyId, daysRemaining: ev.daysRemaining }),
  },

  {
    events:   ['KEY_ROTATION_OVERDUE'],
    subtype:  OPERATIONAL_SUBTYPE.KEY_ROTATION_OVERDUE,
    severity: SEVERITY.MEDIUM,
    confidence: 100,
    title:    (ev) => `Signing key rotation overdue — ${ev.daysOverdue ?? '?'} day(s) past due`,
    description: (ev) =>
      `Active signing key "${ev.keyId ?? '?'}" for client "${ev.clientId ?? '?'}" is ` +
      `${ev.daysOverdue ?? '?'} day(s) past its rotation-due deadline. Automatic rotation may be ` +
      `disabled or failing — investigate.`,
    tags:     ['operational', 'keys', 'rotation'],
    evidence: (ev) => ({ clientId: ev.clientId, keyId: ev.keyId, daysOverdue: ev.daysOverdue }),
  },

  {
    // PG_CIRCUIT_BREAKER_STATE carries every transition ({from, to, reason});
    // only alert on the state that actually indicates pool exhaustion/
    // fast-failing — CLOSED/HALF_OPEN are recovery signals, not incidents.
    events:   ['PG_CIRCUIT_BREAKER_STATE'],
    matches:  (ev) => ev.to === 'OPEN',
    subtype:  OPERATIONAL_SUBTYPE.PG_POOL_EXHAUSTED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    () => `PostgreSQL circuit breaker OPEN — pool exhausted, requests fast-failing`,
    description: (ev) =>
      `The PostgreSQL circuit breaker tripped OPEN (reason="${ev.reason ?? '?'}"). PG-dependent ` +
      `operations are now fast-failing instead of queueing against an exhausted/unavailable pool. ` +
      `The file-based audit chain remains authoritative in single-node mode, but PG-backed features ` +
      `(dual-write, distributed ordering, compliance reporting) are degraded until this recovers.`,
    tags:     ['operational', 'postgres', 'circuit-breaker', 'critical'],
    evidence: (ev) => ({ from: ev.from, to: ev.to, reason: ev.reason }),
  },

  // ── consent revocation/suspension propagation alerting ──────────
  // ConsentRegistry.js already logged these at 'CRITICAL' log level, but
  // (confirmed by grep before this WP) none reached the alerting pipeline —
  // detected but never paged. All three share the same failure shape (PG
  // commit + local cache invalidation succeeded, Redis pub/sub publish to
  // other nodes failed) and the same fix, so all three are covered by one
  // rule rather than fixing only the one names by example and leaving
  // its two siblings (SUSPENSION, bulk ACTOR revocation) silently unpaged.
  {
    events:   [
      'CONSENT_REVOCATION_PROPAGATION_FAILED',
      'CONSENT_SUSPENSION_PROPAGATION_FAILED',
      'CONSENT_REVOCATION_ACTOR_PROPAGATION_FAILED',
    ],
    subtype:  OPERATIONAL_SUBTYPE.CONSENT_PROPAGATION_FAILED,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Consent propagation failed — other nodes not notified (${ev.eventType ?? 'unknown event'})`,
    description: (ev) =>
      `A consent change committed to PostgreSQL and invalidated the local cache, but could not be ` +
      `published to the Redis pub/sub channel (destination="${ev.destination ?? '?'}") for other nodes. ` +
      `consentId="${ev.consentId ?? '?'}", actorId="${ev.actorId ?? '?'}". Other nodes will serve stale ` +
      `cached consent state unless their own subscriber health check blocks them fail-closed. ` +
      `Restore Redis pub/sub connectivity immediately.`,
    tags:     ['governance', 'consent', 'propagation', 'critical'],
    evidence: (ev) => ({
      consentId:     ev.consentId ?? null,
      actorId:       ev.actorId ?? null,
      tenantId:      ev.tenantId ?? null,
      correlationId: ev.correlationId ?? null,
      destination:   ev.destination ?? 'redis-pubsub',
      failureReason: ev.message ?? null,
      retryAttempts: ev.retryAttempts ?? 0,
      willRetry:     ev.willRetry ?? false,
      revokedCount:  ev.revokedCount ?? null,
    }),
  },

];

const GOVERNANCE_RULES = [

  {
    events:   ['RBAC_DENY'],
    subtype:  GOVERNANCE_SUBTYPE.RBAC_VIOLATION,
    severity: SEVERITY.MEDIUM,
    confidence: 100,
    title:    (ev) => `RBAC permission denied — ${ev.actor ?? ev.username ?? 'unknown'} → ${ev.permission ?? ev.action ?? 'unknown'}`,
    description: (ev) =>
      `Access control denied: actor "${ev.actor ?? ev.username ?? '?'}" attempted action ` +
      `"${ev.permission ?? ev.action ?? '?'}" without sufficient privileges. ` +
      `role="${ev.role ?? '?'}", endpoint="${ev.endpoint ?? '?'}". ` +
      `Repeated denials from the same actor may indicate privilege escalation attempts.`,
    tags:     ['governance', 'rbac', 'access-control'],
    evidence: (ev) => ({
      actor:      ev.actor ?? ev.username,
      permission: ev.permission ?? ev.action,
      role:       ev.role,
      endpoint:   ev.endpoint,
      requestId:  ev.requestId,
    }),
  },

  {
    events:   ['OPS_AUTH_INVALID_TOKEN'],
    subtype:  GOVERNANCE_SUBTYPE.OPS_AUTH_FAILURE,
    severity: SEVERITY.HIGH,
    confidence: 95,
    title:    (ev) => `Operations endpoint authentication failure — ${ev.endpoint ?? 'unknown endpoint'}`,
    description: (ev) =>
      `An invalid authentication token was presented to the operations endpoint ` +
      `"${ev.endpoint ?? '?'}". clientIp="${ev.clientIp ?? '?'}". ` +
      `This may indicate an unauthorized party probing the operations API.`,
    tags:     ['governance', 'ops-auth', 'unauthorized'],
    evidence: (ev) => ({
      endpoint:  ev.endpoint,
      clientIp:  ev.clientIp,
      requestId: ev.requestId,
    }),
  },

  // ── governance publish reconciliation ────────────────────────────
  // Both rules match the same event (GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED,
  // emitted by src/core/policy/governance/reconciliation.js) and split
  // severity by divergenceType via the `matches` predicate mechanism (the
  // same one PG_CIRCUIT_BREAKER_STATE above uses): HASH_MISMATCH/
  // VERSION_MISMATCH/PUBLICATION_STATE_INCONSISTENT are cryptographic/version
  // integrity findings (tamper-adjacent) — MISSING_PUBLICATION/MISSING_FILE
  // are structural drift, real but less severe.

  {
    events:   ['GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED'],
    matches:  (ev) => ['HASH_MISMATCH', 'VERSION_MISMATCH', 'PUBLICATION_STATE_INCONSISTENT'].includes(ev.divergenceType),
    subtype:  GOVERNANCE_SUBTYPE.RECONCILIATION_DIVERGENCE,
    severity: SEVERITY.CRITICAL,
    confidence: 100,
    title:    (ev) => `Governance ledger divergence — ${ev.divergenceType ?? 'unknown'} for policy "${ev.policyId ?? '?'}"`,
    description: (ev) =>
      `Startup reconciliation found the file-based policy store diverged from the Postgres governance ` +
      `ledger for policy "${ev.policyId ?? '?'}" (${ev.divergenceType ?? '?'}): ${ev.detail ?? ''} ` +
      `This is a cryptographic/version integrity finding — investigate before trusting either copy.`,
    tags:     ['governance', 'reconciliation', 'integrity', 'critical'],
    evidence: (ev) => ({
      policyId:      ev.policyId,
      publicationId: ev.publicationId,
      version:       ev.version,
      expectedHash:  ev.expectedHash,
      actualHash:    ev.actualHash,
      divergenceType: ev.divergenceType,
      reconciliationResult: ev.reconciliationResult,
    }),
  },

  {
    events:   ['GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED'],
    matches:  (ev) => ['MISSING_PUBLICATION', 'MISSING_FILE'].includes(ev.divergenceType),
    subtype:  GOVERNANCE_SUBTYPE.RECONCILIATION_DIVERGENCE,
    severity: SEVERITY.HIGH,
    confidence: 100,
    title:    (ev) => `Governance ledger divergence — ${ev.divergenceType ?? 'unknown'} for policy "${ev.policyId ?? '?'}"`,
    description: (ev) =>
      `Startup reconciliation found the file-based policy store diverged from the Postgres governance ` +
      `ledger for policy "${ev.policyId ?? '?'}" (${ev.divergenceType ?? '?'}): ${ev.detail ?? ''} ` +
      `This is structural drift — investigate whether the file write after publish failed or was ` +
      `bypassed.`,
    tags:     ['governance', 'reconciliation', 'drift'],
    evidence: (ev) => ({
      policyId:      ev.policyId,
      publicationId: ev.publicationId,
      version:       ev.version,
      expectedHash:  ev.expectedHash,
      actualHash:    ev.actualHash,
      divergenceType: ev.divergenceType,
      reconciliationResult: ev.reconciliationResult,
    }),
  },


  // ── data exposure. DLP_TRANSFORM events (src/core/dlp/dlpService.js) that mean sensitive data REACHED the caller: a DETECT-only rule that found credentials, key
  // material, financial or national-id data in an answer or a tool result, or an exfiltration signal that was only recorded. A rule that REDACTED, MASKED or BLOCKED prevented
  // the exposure and raises nothing (the audit trail has it). The evidence carries rule ids, counts and the two text hashes - never a value.
  {
    events:   ['DLP_TRANSFORM'],
    matches:  (ev) => ['output', 'tool_output'].includes(ev.direction) && ev.action === 'DETECT' && Array.isArray(ev.rules) && ev.rules.some(_isSensitiveRule),
    subtype:  GOVERNANCE_SUBTYPE.DATA_EXPOSURE,
    severity: SEVERITY.HIGH,
    confidence: 80,
    title:    (ev) => `Possible data exposure in ${ev.direction === 'tool_output' ? 'a tool result' : 'a model answer'} — ${ev.rules.filter(_isSensitiveRule).join(', ')}`,
    description: (ev) =>
      `A DLP rule in DETECT mode (policy "${ev.policyId ?? '?'}") found ${ev.findings ?? '?'} sensitive item(s) (${(ev.rules || []).join(', ')}) in ${ev.direction === 'tool_output' ? 'a tool result' : 'an answer'} ` +
      `that was delivered unchanged. Decide whether this is an exposure incident (see the notification drafts for this alert); the values are not in the alert.`,
    tags:     ['governance', 'dlp', 'data-exposure'],
    evidence: (ev) => _dlpEvidence(ev),
  },
  {
    events:   ['DLP_TRANSFORM'],
    matches:  (ev) => ev.action === 'DETECT' && Array.isArray(ev.rules) && ev.rules.some((r) => String(r).startsWith('EXFIL:')),
    subtype:  GOVERNANCE_SUBTYPE.DATA_EXPOSURE,
    severity: SEVERITY.CRITICAL,
    confidence: 70,
    title:    (ev) => `Possible data exfiltration through an answer — ${ev.rules.filter((r) => String(r).startsWith('EXFIL:')).join(', ')}`,
    description: (ev) =>
      `An exfiltration rule in DETECT mode (policy "${ev.policyId ?? '?'}") flagged an answer: ${(ev.rules || []).join(', ')}. The answer was delivered unchanged.`,
    tags:     ['governance', 'dlp', 'data-exposure', 'exfiltration'],
    evidence: (ev) => ({ ..._dlpEvidence(ev), exfiltration: ev.exfiltration ?? null }),
  },
];

// rule ids that mean "something that must not be seen": credentials, key material, financial and national-id data (personal data alone - e-mail, phone - is not an incident by itself)
const _SENSITIVE_RULE = /^(KEY_|PEM_BLOCK$|JWT$|CODE_SECRET$|CARD$|IBAN$|CNP$|PESEL$|BSN$|DE_TAX_ID$|US_SSN$|ES_DNI_NIE$|UK_NINO$)/;
function _isSensitiveRule(r) { return _SENSITIVE_RULE.test(String(r)); }
function _dlpEvidence(ev) {
  return { policyId: ev.policyId, direction: ev.direction, action: ev.action, rules: ev.rules, findings: ev.findings, inputHashBefore: ev.inputHashBefore, inputHashAfter: ev.inputHashAfter, requestId: ev.requestId, tenantId: ev.tenantId };
}

function analyze(event) {
  const eventName = event.eventType ?? '';

  for (const rule of [...OPERATIONAL_RULES, ...GOVERNANCE_RULES]) {
    if (!rule.events.includes(eventName)) continue;
    // #9: optional payload-level predicate, additive — every existing
    // rule omits `matches` and continues to trigger on eventType alone.
    // Lets one rule cover a multi-state event (e.g. PG_CIRCUIT_BREAKER_STATE)
    // and only alert for the state transition that actually warrants one.
    if (typeof rule.matches === 'function' && !rule.matches(event)) continue;

    const isGovernance = GOVERNANCE_RULES.includes(rule);
    return {
      triggered: true,
      alert: {
        type:        isGovernance ? ALERT_TYPE.GOVERNANCE : ALERT_TYPE.OPERATIONAL,
        subtype:     rule.subtype,
        severity:    rule.severity,
        confidence:  rule.confidence,
        title:       rule.title(event),
        description: rule.description(event),
        tags:        rule.tags,
        evidence:    rule.evidence(event),
        context:     {},
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

  return { triggered: false };
}

module.exports = { analyze };
