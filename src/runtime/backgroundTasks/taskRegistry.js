'use strict';

/**
 * Background Task Registry — Finding 3.6 remediation.
 *
 * Explicit, declarative classification of every background/async execution
 * path in the process. "Classification must be explicit in code, no
 * implicit assumptions" — every task that goes through
 * BackgroundTaskRunner.runTask() must have an entry here; runTask() throws
 * at call time if a task name has no registry entry, so a new background
 * job cannot silently ship unclassified.
 *
 * ── Criticality levels ────────────────────────────────────────────────────
 *
 *   'startup-critical'  Must still fail fast. Reserved for one-shot startup
 *                       preconditions (PG/Redis unreachable, replay
 *                       protection unavailable, consent subsystem
 *                       unavailable, cryptographic init failure, mandatory
 *                       migration failure). BackgroundTaskRunner does NOT
 *                       swallow errors for this class — it rethrows after
 *                       logging/metrics so the caller's existing
 *                       process.exit(1) logic (e.g. server.js's
 *                       `await consentSubscriber.start()`) is unaffected.
 *                       No *recurring* background tick is classified this
 *                       way — see 'critical' below for why.
 *
 *   'critical'          Security/compliance-relevant RECURRING background
 *                       work. Failures must be loudly alerted on (ERROR
 *                       level, dedicated metric reason) but must NOT crash
 *                       the process — a stuck key-rotation tick or a
 *                       transient revocation-reconnect hiccup taking down
 *                       request serving would itself be the exact
 *                       availability regression this finding is about.
 *                       Fail-fast for these components is enforced at
 *                       startup (their `start()` is 'startup-critical');
 *                       once running, ongoing tick failures are isolated
 *                       and retried on the next scheduled interval.
 *
 *   'non-critical'      Auxiliary work: webhook delivery/retry, telemetry/
 *                       log shipping, cache/snapshot refresh, cleanup,
 *                       notifications, gap scanning. Never fatal.
 *
 * ── retryPolicy ───────────────────────────────────────────────────────────
 *
 *   'internal'  The task's own function already implements retry/backoff
 *               (rootScheduler, rotationScheduler, transparency scanner,
 *               persistenceRecovery worker all do). BackgroundTaskRunner
 *               does not add its own retry loop on top — that would double
 *               the effective retry count and interact badly with each
 *               subsystem's own backoff timing.
 *   'runner'    The task has no internal retry logic; BackgroundTaskRunner
 *               applies its own bounded retry (see runner's `retries`
 *               option) before giving up.
 *   'none'      Single attempt; failure is logged/counted and left for the
 *               next scheduled invocation (most setInterval-driven jobs).
 */

const REGISTRY = {
  'key-rotation-tick': {
    subsystem:   'crypto-key-management',
    owner:       'platform-security',
    criticality: 'critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'interval (KEY_ROTATION_CHECK_INTERVAL_MS, self-rescheduling)',
    file:        'services/artifact/rotationScheduler.js',
  },
  'transparency-gap-scan': {
    subsystem:   'transparency-log',
    owner:       'platform-security',
    criticality: 'non-critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'interval (TRANSPARENCY_SCANNER_INTERVAL, self-rescheduling)',
    file:        'src/core/transparency/scanner/index.js',
  },
  'transparency-root-generation': {
    subsystem:   'transparency-log',
    owner:       'platform-security',
    criticality: 'non-critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'interval + entry-count poll (self-rescheduling)',
    file:        'src/core/transparency/rootScheduler.js',
  },
  'queue-depth-monitor': {
    subsystem:   'persistence',
    owner:       'platform-core',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'interval (QODIQA_QUEUE_MONITOR_INTERVAL_MS, self-rescheduling)',
    file:        'src/core/persistenceRecovery/queueMonitor.js',
  },
  'audit-pg-lag-monitor': {
    subsystem:   'audit-log',
    owner:       'platform-security',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval',
    file:        'src/core/audit/pgLagMonitor.js',
  },
  // S4: audit_chain counter vs count(*) cross-check (OD-5) — alerts on drift, never repairs.
  'audit-mirror-count-reconcile': {
    subsystem:   'audit-log',
    owner:       'platform-security',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval (QODIQA_AUDIT_MIRROR_RECONCILE_INTERVAL_MS, default 6 h)',
    file:        'src/core/audit/mirrorCountReconciler.js',
  },
  'alert-escalation-scan': {
    subsystem:   'alerting',
    owner:       'platform-ops',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval (SCAN_INTERVAL_MS)',
    file:        'src/alerting/escalation/EscalationService.js',
  },
  'log-shipping-dispatch': {
    subsystem:   'observability',
    owner:       'platform-ops',
    criticality: 'non-critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'per-record, queue-driven',
    file:        'src/observability/logShipping/queue.js',
  },
  'persistence-recovery-worker': {
    subsystem:   'persistence',
    owner:       'platform-core',
    criticality: 'critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'self-rescheduling poll loop',
    file:        'src/core/persistenceRecovery/worker.js',
  },
  'persistence-recovery-journal-worker': {
    subsystem:   'persistence',
    owner:       'platform-core',
    criticality: 'critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'self-rescheduling poll loop',
    file:        'src/core/persistenceRecovery/journalWorker.js',
  },
  'webhook-delivery': {
    subsystem:   'webhooks',
    owner:       'platform-integrations',
    criticality: 'non-critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'invoked by persistence-recovery-worker per queued delivery',
    file:        'src/core/webhooks/webhookDelivery.js',
  },
  'dashboard-sse-snapshot': {
    subsystem:   'dashboard',
    owner:       'platform-ops',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval (SNAPSHOT_INTERVAL_MS)',
    file:        'src/dashboard/sseManager.js',
  },
  'postgres-readiness-monitor': {
    subsystem:   'infra-postgres',
    owner:       'platform-core',
    criticality: 'non-critical',
    retryPolicy: 'internal',
    timeoutMs:   null,
    frequency:   'setInterval',
    file:        'src/infra/postgres/pool.js',
  },
  'vault-kek-reauth': {
    subsystem:   'infra-keys',
    owner:       'platform-security',
    criticality: 'critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval (KEK re-auth lease renewal)',
    file:        'src/infra/keys/providers/vault.js',
  },
  'vault-transit-reauth': {
    subsystem:   'infra-keys',
    owner:       'platform-security',
    criticality: 'critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval (Transit re-auth lease renewal)',
    file:        'src/infra/keys/providers/vault.js',
  },
  'audit-retention-cycle': {
    subsystem:   'audit-log',
    owner:       'platform-security',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval (server.js)',
    file:        'server.js',
  },
  // step 6: signed audit-chain checkpoints. Registered step 7 — the scheduler shipped
  // without this entry, so its first tick (60 s after boot) threw BACKGROUND_TASK_UNCLASSIFIED as an unhandled
  // rejection and ended the process.
  'audit-checkpoint': {
    subsystem:   'audit-log',
    owner:       'platform-security',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'setInterval (60 s tick; a checkpoint every QODIQA_AUDIT_CHECKPOINT_EVERY entries / MAX_AGE_MS)',
    file:        'src/core/audit/checkpoint/checkpointWriter.js',
  },
  'redis-sentinel-recovery-notify': {
    subsystem:   'infra-redis',
    owner:       'platform-core',
    criticality: 'non-critical',
    retryPolicy: 'none',
    timeoutMs:   null,
    frequency:   'event-driven (topology-change MASTER_CHANGE)',
    file:        'src/infra/redis/managedClient.js',
  },
};

function getTaskDefinition(taskName) {
  return REGISTRY[taskName] || null;
}

function listTasks() {
  return Object.keys(REGISTRY).map(taskName => ({ taskName, ...REGISTRY[taskName] }));
}

module.exports = { REGISTRY, getTaskDefinition, listTasks };
