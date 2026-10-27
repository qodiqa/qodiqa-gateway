'use strict';

/**
 * Multi-Instance Startup Guard — Component #11 / SCAL-11
 *
 * ── Single-node mode (default) ──────────────────────────────────────────────
 * QODIQA's audit chain derives ordering from a process-local in-memory array
 * (const chain = [] in audit-log.js). Two concurrent processes reading the same
 * NDJSON file would each build independent chain[] arrays, then diverge the
 * moment either calls append() — producing two conflicting prevHash lineages
 * with no shared ordering authority and no cryptographic continuity.
 *
 * checkSingleInstance() must be called once during server startup, before any
 * audit append, to prevent accidental multi-instance deployment. Unchanged
 * from its original behavior — see docs/protocol/AUDIT-SCHEMA-V8.md.
 *
 * Detection scope:
 *   NODE_APP_INSTANCE  — set by PM2 cluster mode ('0' on primary, '1+'  on workers)
 *   cluster.isWorker   — set by Node.js built-in cluster.fork()
 *   KUBERNETES_SERVICE_HOST — set by the Kubernetes API server in every pod's
 *     environment (SCAL-13). Neither of the two checks above can see this:
 *     Kubernetes Deployments/ReplicaSets do not set NODE_APP_INSTANCE, and
 *     each replica is a separate OS process/pod, not a cluster.fork() worker
 *     of this one — so N identical replicas each pass both existing checks
 *     and each believes it is the sole writer. Kubernetes gives a pod no
 *     built-in signal for its own replica count (Deployments don't inject
 *     one; the Downward API only projects fields of the pod itself, not its
 *     parent's spec.replicas), so this code cannot distinguish "the 1 replica
 *     of a replicas:1 Deployment" from "1 of N replicas of a replicas:N
 *     Deployment" — only that it is running under Kubernetes at all. Given
 *     that, and given fail-closed is the required posture when ownership
 *     cannot be safely determined, detecting KUBERNETES_SERVICE_HOST refuses
 *     to start in single-node mode unless the operator explicitly
 *     acknowledges a single-replica topology (QODIQA_K8S_SINGLE_REPLICA=true)
 *     or switches to distributed mode (correct for any replica count,
 *     including 1). See docs/deployment/kubernetes-probes.md.
 *
 * ── Distributed mode (QODIQA_AUDIT_ORDERING_MODE=distributed) ──────────────
 * Multi-instance startup is the entire point of this mode (SCAL-11
 * remediation — PostgreSQL's audit_chain_head row lock is the shared
 * ordering authority; see distributedOrdering.js), so the PM2/cluster.fork()
 * block above is intentionally skipped. checkDistributedPreconditions()
 * instead verifies a basic dependency-readiness precondition — the same
 * category of check as the StatefulSet's existing wait-for-redis init
 * container, not a leader-election or "only one replica may start"
 * restriction: every replica runs this same check independently and may
 * proceed once PostgreSQL is reachable.
 *
 * checkStartupPreconditions() is the mode-aware entry point server.js calls.
 * Single-node mode's half is synchronous (unchanged). Distributed mode's
 * half is async (it queries PostgreSQL) and must run after
 * pgPool.initialize() has been called — see server.js's startup sequence.
 *
 * ── deployment mode resolver integration ────────────────────────────
 * ORDERING_MODE below no longer reads process.env.QODIQA_AUDIT_ORDERING_MODE
 * directly — it delegates to src/infra/config/deploymentMode.js's
 * getResolvedDeploymentConfig(), the single authoritative resolver for
 * QODIQA_DEPLOYMENT_MODE. That resolver is memoized per-process and is
 * populated by server/startup.js's applyDeploymentMode() call, which runs
 * before this module is required — so this constant observes the
 * authoritative resolution regardless of exactly when this file is
 * required, as long as it is required afterward (guaranteed by
 * server/startup.js's require order). When QODIQA_DEPLOYMENT_MODE is unset,
 * the resolver falls through to the legacy QODIQA_AUDIT_ORDERING_MODE var,
 * so this constant's value is unchanged from every release.
 *
 * checkDistributedPreconditions() additionally now verifies (and, when
 * QODIQA_PG_AUTO_MIGRATE=true, auto-applies) migration 026 before probing
 * audit_chain_head, and the new assertNoIllegalTopology() adds an invariant:
 * PG enabled + ordering != distributed + more than one replica is an
 * illegal, fail-fast startup state (see that function's header comment).
 */

const cluster = require('cluster');
const { writeDiagnostic } = require('../../runtime/rawStderrDiagnostic');
const { notifyCriticalStartupFailure } = require('../../runtime/earlyCriticalNotify');
const { getResolvedDeploymentConfig } = require('../../infra/config/deploymentMode');

const ORDERING_MODE = getResolvedDeploymentConfig().auditOrderingMode;

/**
 * Checks that the current process is the sole instance allowed to own the
 * audit chain (single-node mode only). Exits with code 1 if a multi-instance
 * condition is detected.
 *
 * All parameters are injectable for testing:
 *   _env      — environment variables object (default: process.env)
 *   _isWorker — cluster worker flag (default: cluster.isWorker)
 *   _exit     — exit function (default: process.exit)
 */
function checkSingleInstance({ _env = process.env, _isWorker = cluster.isWorker, _exit = (code) => process.exit(code) } = {}) {
  const pmInstance = _env.NODE_APP_INSTANCE;

  // PM2 cluster mode assigns NODE_APP_INSTANCE='0' to the first instance and
  // '1', '2', ... to subsequent workers.  Block any non-zero instance.
  if (pmInstance !== undefined && pmInstance !== '0') {
    _writeFatal('AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN', {
      reason:            'QODIQA audit chain is single-node. PM2 cluster workers produce divergent chains with no shared ordering authority.',
      NODE_APP_INSTANCE: pmInstance,
      action:            'Set instances: 1 in your PM2 ecosystem config, or run as a single process. To run multiple instances, set QODIQA_AUDIT_ORDERING_MODE=distributed.',
      ref:               'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _exit(1);
    return;
  }

  // Node.js built-in cluster: cluster.isWorker is true when this process was
  // spawned via cluster.fork().
  if (_isWorker) {
    _writeFatal('AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN', {
      reason:   'QODIQA audit chain is single-node. Node cluster workers produce divergent chains.',
      workerId: cluster.worker?.id ?? null,
      action:   'Do not use cluster.fork() with QODIQA. Run as a single process, or set QODIQA_AUDIT_ORDERING_MODE=distributed.',
      ref:      'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _exit(1);
    return;
  }

  // Kubernetes topology (SCAL-13): KUBERNETES_SERVICE_HOST is injected by the
  // API server into every pod, independent of replica count — this process
  // cannot tell from its own environment whether it is the only replica or
  // one of many (see module header comment). Fail closed unless the operator
  // has explicitly acknowledged a single-replica topology, or is running
  // distributed mode (which is correct for any replica count and never
  // reaches this function — see checkStartupPreconditions below).
  const inKubernetes = typeof _env.KUBERNETES_SERVICE_HOST === 'string' && _env.KUBERNETES_SERVICE_HOST.length > 0;
  if (inKubernetes && _env.QODIQA_K8S_SINGLE_REPLICA !== 'true') {
    _writeFatal('AUDIT_CHAIN_KUBERNETES_TOPOLOGY_UNVERIFIED', {
      reason: 'QODIQA audit chain is single-node, but this process is running inside Kubernetes ' +
              '(KUBERNETES_SERVICE_HOST is set). Kubernetes gives a pod no way to determine its own ' +
              'replica count, so single-node mode cannot safely verify it is the only writer — running ' +
              'with replicas > 1 would let multiple pods append concurrently with no shared ordering ' +
              'authority, corrupting the chain.',
      action: 'For any Deployment/StatefulSet, regardless of replica count, set ' +
              'QODIQA_AUDIT_ORDERING_MODE=distributed so PostgreSQL becomes the shared ordering ' +
              'authority (see docs/deployment/kubernetes-probes.md). If you are certain this is a single-replica ' +
              'deployment and want to keep single-node (file-based) mode, set ' +
              'QODIQA_K8S_SINGLE_REPLICA=true to acknowledge this and start anyway.',
      ref: 'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _exit(1);
    return;
  }
}

/**
 * Migration 026 (audit_chain_distributed_ordering) creates audit_chain_head,
 * the table checkDistributedPreconditions() probes below — queried by its
 * own version number in qodiqa_migrations rather than inferred from
 * audit_chain_head's existence, so a not-yet-migrated database and a real
 * connectivity failure can be told apart precisely.
 */
async function _isMigration026Applied(_pgPool) {
  const result = await _pgPool.query(
    'SELECT 1 FROM qodiqa_migrations WHERE version = $1',
    [26],
    'distributed_migration_verify',
  );
  return result.rows.length > 0;
}

/**
 * Produces an accurate, non-misleading reason string for a PG query failure
 * during startup preconditions.
 *
 * pool.js's query circuit breaker (pgCircuitBreaker.js, FAILOVER-2)
 * fast-fails every query with a PG_CIRCUIT_OPEN-coded error while the
 * breaker is open, WITHOUT ever contacting the database — a real but
 * transient condition (e.g. a burst of unrelated connection-pool pressure
 * elsewhere in the process) that is categorically different from PostgreSQL
 * actually being unreachable. Reporting both under the same generic
 * "could not reach/query" wording made it impossible for an operator to
 * tell "PostgreSQL is down" apart from "this process's own circuit breaker
 * is temporarily protecting an already-healthy database from a retry
 * storm" — the latter self-resolves once QODIQA_PG_CB_RECOVERY_MS elapses
 * (default 30s) and does not indicate any actual PostgreSQL problem.
 */
function _describePgFailure(err) {
  if (err && err.code === 'PG_CIRCUIT_OPEN') {
    return {
      reason: 'The PostgreSQL query circuit breaker is currently OPEN — this process is ' +
              'fast-failing queries without contacting the database, most likely due to a ' +
              'recent burst of unrelated connection-pool pressure, not necessarily because ' +
              'PostgreSQL itself is unreachable.',
      action: 'Wait for the circuit breaker to attempt recovery (QODIQA_PG_CB_RECOVERY_MS, ' +
              'default 30s), then retry. If this persists across multiple attempts, then ' +
              'investigate actual PostgreSQL connectivity/QODIQA_PG_POOL_MAX sizing — see ' +
              'src/infra/postgres/pgCircuitBreaker.js.',
      circuitBreakerOpen: true,
    };
  }
  return {
    reason: `Could not reach PostgreSQL: ${err.message}`,
    action: 'Run `node src/infra/postgres/migrate.js` (migration 026) and verify QODIQA_PG_* connectivity before starting in distributed mode.',
    circuitBreakerOpen: false,
  };
}

/**
 * Distributed-mode startup precondition: refuses to start unless
 * QODIQA_PG_ENABLED=true, migration 026 is verified applied (
 * auto-applied first when QODIQA_PG_AUTO_MIGRATE=true and missing), and the
 * audit_chain_head ordering table is actually reachable. Fails closed
 * (FATAL + exit(1)) rather than starting in a state where the first
 * append() call would discover the problem. Never silently downgrades to
 * file-based persistence.
 *
 * Concurrent auto-migrate safety: the
 * `_pgPool.runMigrations()` call below (pool.js) holds a PostgreSQL
 * session-scoped advisory lock for the ENTIRE migration pass, so multiple
 * replicas discovering the same missing migration simultaneously (e.g. every
 * pod of a freshly-rolled-out distributed-mode Deployment, all starting at
 * once against a database that has never been migrated) serialize on that
 * lock rather than racing each other's DDL. This is real single-writer
 * protection, not just a documentation-level recommendation — see
 * src/infra/postgres/pool.js's withAdvisoryLock()/runMigrations() and
 * test/integration/audit-chain-distributed-migration.integration.test.js for a real
 * multi-process reproduction.
 *
 * All parameters are injectable for testing:
 *   _pgPool — the PG pool module (default: src/infra/postgres/pool.js)
 *   _config — resolved deployment config (default: getResolvedDeploymentConfig())
 *   _exit   — exit function (default: process.exit)
 */
async function checkDistributedPreconditions({
  _pgPool = require('../../infra/postgres/pool'),
  _config = getResolvedDeploymentConfig(),
  _exit   = (code) => process.exit(code),
} = {}) {
  if (!_pgPool.isEnabled()) {
    _writeFatal('AUDIT_CHAIN_DISTRIBUTED_PG_REQUIRED', {
      reason: 'QODIQA_AUDIT_ORDERING_MODE=distributed requires QODIQA_PG_ENABLED=true — PostgreSQL is the ordering authority in distributed mode.',
      action: 'Set QODIQA_DEPLOYMENT_MODE=distributed (recommended — resolves this automatically), or set QODIQA_PG_ENABLED=true and configure QODIQA_PG_* connection settings, or unset QODIQA_AUDIT_ORDERING_MODE to run single-node.',
      ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _exit(1);
    return false;
  }

  // ── Migration verification ─────────────────────────────────────
  // Checked before the audit_chain_head probe below: on a database where
  // migration 026 was never applied, that probe would throw with an
  // undifferentiated "relation does not exist" error — folding a simple
  // "migration missing" state into the generic "PG unreachable" diagnostic.
  // Querying qodiqa_migrations directly lets a real connectivity failure
  // (caught below, reported as AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE — the
  // same event a failure of the audit_chain_head probe itself reports, since
  // both mean "could not talk to PostgreSQL") stay distinct from a
  // successful-but-missing-row state (AUDIT_CHAIN_MIGRATION_MISSING below).
  let migrationApplied;
  try {
    migrationApplied = await _isMigration026Applied(_pgPool);
  } catch (err) {
    if (err.code === '42P01') {
      // undefined_table: qodiqa_migrations itself has never been created —
      // a genuinely virgin database (no migration has ever run there).
      // migrate.js's runMigrations() bootstraps this table itself
      // (CREATE TABLE IF NOT EXISTS, as its first step), so this is a
      // legitimate "migration not applied" state that auto-migrate can
      // actually resolve — not a connectivity failure. Fall through to the
      // same auto-migrate / AUDIT_CHAIN_MIGRATION_MISSING handling below
      // rather than reporting PG_UNREACHABLE for something fixable.
      migrationApplied = false;
    } else {
      const { reason, action, circuitBreakerOpen } = _describePgFailure(err);
      _writeFatal('AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE', {
        reason: `Could not query the migration tracking table (qodiqa_migrations). ${reason}`,
        error:  err.message,
        circuitBreakerOpen,
        action,
        ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
      });
      _exit(1);
      return false;
    }
  }

  if (!migrationApplied && _config.autoMigrateEnabled) {
    try {
      await _pgPool.runMigrations();
      migrationApplied = await _isMigration026Applied(_pgPool);
    } catch (err) {
      const circuitBreakerOpen = err.code === 'PG_CIRCUIT_OPEN';
      _writeFatal('AUDIT_CHAIN_AUTO_MIGRATE_FAILED', {
        reason: `QODIQA_PG_AUTO_MIGRATE=true but automatic migration failed: ${err.message}` +
                (circuitBreakerOpen ? ' (the PostgreSQL query circuit breaker is currently OPEN — see QODIQA_PG_CB_RECOVERY_MS)' : ''),
        circuitBreakerOpen,
        action: 'Run `node src/infra/postgres/migrate.js` manually and inspect the error.',
        ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
      });
      _exit(1);
      return false;
    }
  }

  if (!migrationApplied) {
    _writeFatal('AUDIT_CHAIN_MIGRATION_MISSING', {
      reason: 'Migration 026 (audit_chain_distributed_ordering) is not recorded in qodiqa_migrations. ' +
              'Distributed mode requires this migration — it creates audit_chain_head, the ordering authority.',
      expectedMigration:     26,
      autoMigrateAttempted:  _config.autoMigrateEnabled,
      action: 'Run `node src/infra/postgres/migrate.js` to apply pending migrations, or set ' +
              'QODIQA_PG_AUTO_MIGRATE=true to have this happen automatically at startup.',
      ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _exit(1);
    return false;
  }

  try {
    const result = await _pgPool.query('SELECT 1 FROM audit_chain_head', [], 'audit_chain_head_probe');
    if (result.rows.length === 0) {
      throw new Error('audit_chain_head has no seed row');
    }
  } catch (err) {
    const { reason, action, circuitBreakerOpen } = _describePgFailure(err);
    _writeFatal('AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE', {
      reason: `Could not reach the audit_chain_head ordering table. ${reason}`,
      error:  err.message,
      circuitBreakerOpen,
      action,
      ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _exit(1);
    return false;
  }

  return true;
}

/**
 * Mode-aware startup entry point. Single-node mode delegates to
 * checkSingleInstance() (synchronous, unchanged behavior). Distributed mode
 * delegates to checkDistributedPreconditions() (async — must be awaited
 * after pgPool.initialize()).
 *
 * @returns {Promise<boolean>} true if startup may proceed (single-node mode
 *   always resolves true unless it has already called process.exit(1)).
 */
async function checkStartupPreconditions(opts = {}) {
  if (ORDERING_MODE === 'distributed') {
    return checkDistributedPreconditions(opts);
  }
  checkSingleInstance(opts);
  return true;
}

/**
 * Illegal multi-instance topology assertion —.
 *
 * Illegal state: PostgreSQL enabled AND ordering mode != distributed AND
 * more than one replica. This specifically targets a multi-replica
 * single-node deployment (e.g. deploy/kubernetes/overlays/single-node/'s
 * StatefulSet, which legitimately runs multiple replicas today via a
 * per-pod exclusive audit-log file) that ALSO opts into the legacy Phase-1
 * PostgreSQL dual-write mirror (QODIQA_PG_ENABLED=true): each replica would
 * then independently dual-write to the shared audit_chain table from its
 * own process-local prevHash lineage, with no shared ordering lock — the
 * same divergent-chain failure mode checkSingleInstance() already guards
 * against for the file-only case, just reachable via PostgreSQL instead. It
 * does NOT fire for the common multi-replica-file-only topology (no PG
 * mirror), which is safe by construction (each replica's file chain is
 * independent by design in single-node mode).
 *
 * Unlike checkDistributedPreconditions() (distributed-mode-only, async,
 * requires a PG round-trip), this assertion is synchronous — pgPool
 * enablement and the resolved deployment config are both immediately
 * available — so it can and must run unconditionally, regardless of
 * ordering mode, immediately after pgPool.initialize() in
 * server/startup.js, not gated behind a mode branch the way
 * checkDistributedPreconditions() is.
 *
 * Replica count is operator-declared (QODIQA_REPLICA_COUNT, defaulting to 1
 * — see src/infra/config/deploymentMode.js): Kubernetes gives a pod no
 * built-in way to learn its own Deployment/StatefulSet spec.replicas value
 * (see this file's header comment for the identical, already-documented gap
 * behind QODIQA_K8S_SINGLE_REPLICA).
 *
 * All parameters are injectable for testing:
 *   _pgPool — the PG pool module (default: src/infra/postgres/pool.js)
 *   _config — resolved deployment config (default: getResolvedDeploymentConfig())
 *   _exit   — exit function (default: process.exit)
 */
function assertNoIllegalTopology({
  _pgPool = require('../../infra/postgres/pool'),
  _config = getResolvedDeploymentConfig(),
  _exit   = (code) => process.exit(code),
} = {}) {
  const pgEnabled = _pgPool.isEnabled();
  if (pgEnabled && ORDERING_MODE !== 'distributed' && _config.replicaCount > 1) {
    _writeFatal('AUDIT_CHAIN_ILLEGAL_TOPOLOGY', {
      reason: `PostgreSQL is enabled, ordering mode is "${ORDERING_MODE}" (not distributed), and ` +
              `QODIQA_REPLICA_COUNT=${_config.replicaCount} — multiple replicas would each ` +
              'independently dual-write to the shared PostgreSQL audit_chain table with no shared ' +
              'ordering authority, silently corrupting the chain.',
      detectedTopology: { pgEnabled, orderingMode: ORDERING_MODE, replicaCount: _config.replicaCount },
      expected: 'Either QODIQA_PG_ENABLED=false for a multi-replica single-node deployment, or exactly ' +
                'one replica, or QODIQA_DEPLOYMENT_MODE=distributed so PostgreSQL becomes the shared ' +
                'ordering authority for any replica count.',
      action: 'Set QODIQA_DEPLOYMENT_MODE=distributed, or reduce to a single replica, or set ' +
              'QODIQA_PG_ENABLED=false.',
      ref: 'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _exit(1);
    return false;
  }
  return true;
}

// See src/runtime/rawStderrDiagnostic.js for the single shared
// implementation of the fail-safe stderr write path this delegates to.
//
// Also fires a best-effort CRITICAL webhook notification (MON-3) — see
// src/runtime/earlyCriticalNotify.js's header comment for why this is
// fire-and-forget (not awaited) rather than blocking the exit that follows
// every call site of this function. The stderr line above is written first
// and remains the always-reliable signal; the notification is additive.
function _writeFatal(eventType, extra) {
  writeDiagnostic('FATAL', eventType, extra);
  notifyCriticalStartupFailure({ eventType, deploymentMode: ORDERING_MODE, ...extra }).catch(() => {});
}

module.exports = {
  checkSingleInstance,
  checkDistributedPreconditions,
  checkStartupPreconditions,
  assertNoIllegalTopology,
  ORDERING_MODE,
};
