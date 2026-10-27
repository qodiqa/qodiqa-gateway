'use strict';

/**
 * QODIQA Deployment Mode Resolver —
 *
 * Prior to this module, whether QODIQA ran in "distributed" mode was decided
 * by three independent, uncoordinated switches, each interpreted by its own
 * subsystem:
 *   - QODIQA_PG_ENABLED            (src/infra/postgres/pool.js)
 *   - QODIQA_AUDIT_ORDERING_MODE   (src/core/audit/multiInstanceGuard.js)
 *   - migration 026 (audit_chain_head) having actually been applied
 *
 * That model allows partially-configured states (e.g. PG enabled, ordering
 * left at single-node, multiple replicas running) that silently corrupt the
 * audit chain's ordering guarantees. This module introduces one deployment
 * abstraction, QODIQA_DEPLOYMENT_MODE ('single-node' | 'distributed'), as the
 * single authoritative source of truth for production topology.
 *
 * ── Precedence ────────────────────────────────────────────────────────────
 * QODIQA_DEPLOYMENT_MODE unset  → fully legacy: QODIQA_PG_ENABLED and
 *   QODIQA_AUDIT_ORDERING_MODE control everything, exactly as before this
 *   module existed. Existing single-node and distributed deployments that
 *   have not adopted the new variable continue to work unchanged.
 * QODIQA_DEPLOYMENT_MODE='distributed' → highest precedence. Resolves to PG
 *   enabled, distributed ordering, migration verification required — no
 *   other variable is read for these three switches. Legacy vars are ignored
 *   for this decision (a "compatibility override" only in the sense that they
 *   remain meaningful when the new variable is absent, not that they can
 *   contradict it once present).
 * QODIQA_DEPLOYMENT_MODE='single-node' → forces single-node ordering. PG
 *   enablement still comes from the legacy QODIQA_PG_ENABLED var, since
 *   single-node mode explicitly continues to permit the optional Phase-1 PG
 * dual-write mirror ("existing behaviour preserved" — see the spec's
 *   Runtime Invariants section).
 * Any other value → invalid configuration. Fails startup rather than
 *   silently falling back to legacy — a typo'd deployment mode is exactly the
 *   "wrong topology, discovered late" failure this module exists to prevent.
 *
 * ── Integration ───────────────────────────────────────────────────────────
 * applyDeploymentMode() must run at the very top of server/startup.js,
 * immediately after `require('dotenv').config()` and before every other
 * require() in that file. Two independent things happen as a result:
 *
 *   1. getResolvedDeploymentConfig()'s result is memoized for the lifetime of
 *      the process. src/core/audit/multiInstanceGuard.js computes its
 *      ORDERING_MODE constant at require() time by calling
 *      getResolvedDeploymentConfig() directly (not by re-reading env vars),
 *      so it observes the authoritative resolution regardless of exactly
 *      when it is required, as long as it is required after this call —
 *      which server/startup.js's require order guarantees.
 *
 *   2. The two legacy env vars (QODIQA_PG_ENABLED, QODIQA_AUDIT_ORDERING_MODE)
 *      are normalized in place to their resolved effective values. This is
 *      for the benefit of the many call sites across this codebase that read
 *      those two vars live, on every call, rather than through this resolver
 *      (src/infra/postgres/pool.js's initialize(), mirrorConsistencyCheck.js,
 *      retentionPrivilegeCheck.js, several scripts). Because each of those
 *      reads process.env fresh every time, normalizing it once here is
 *      behaviorally identical to each of them independently consulting this
 *      resolver — no subsystem is left to interpret QODIQA_DEPLOYMENT_MODE
 *      on its own; they all continue reading the two legacy vars, but those
 *      vars are now always authoritatively derived from the one source of
 *      truth here.
 */

const { writeDiagnostic } = require('../../runtime/rawStderrDiagnostic');
const { notifyCriticalStartupFailure } = require('../../runtime/earlyCriticalNotify');

const VALID_MODES = new Set(['single-node', 'distributed']);
const ADR_REF = 'docs/protocol/AUDIT-SCHEMA-V8.md';

// ── Resolution ────────────────────────────────────────────────────────────

/**
 * @param {NodeJS.ProcessEnv} env
 * @returns {{ mode: 'single-node'|'distributed'|null, error: string|null }}
 *   mode === null && error === null  → QODIQA_DEPLOYMENT_MODE unset (legacy path)
 *   mode === null && error !== null  → set to an unrecognized value
 *
 * WHITESPACE IS DELIBERATELY NOT TRIMMED — this is a considered decision,
 * not an oversight. QODIQA_DEPLOYMENT_MODE=" distributed" (a stray leading
 * space from a shell-quoting mistake, a Helm values.yaml block-scalar
 * indentation error, or a copy-paste from a rendered table) is treated as an
 * UNRECOGNIZED value and fails startup, exactly like any other typo. The
 * alternative — silently trimming and accepting it — would mean a
 * malformed-but-plausible-looking value takes effect exactly as if it had
 * been typed correctly, with no signal to the operator that anything was
 * off. For every OTHER unrecognized value this module already fails closed
 * loudly rather than guessing at intent (see the module header's "Any other
 * value" precedence rule); trimming would carve out a silent special case
 * for whitespace specifically, undermining that same guarantee for no
 * principled reason. An operator who hits this gets an immediate, actionable
 * FATAL diagnostic at deploy time — never a silently-accepted-but-wrong
 * production topology discovered later.
 */
function resolveDeploymentMode(env = process.env) {
  const raw = env.QODIQA_DEPLOYMENT_MODE;
  if (raw === undefined || raw === '') return { mode: null, error: null };
  if (!VALID_MODES.has(raw)) {
    return {
      mode: null,
      error: `QODIQA_DEPLOYMENT_MODE is set to an unrecognized value "${raw}" — must be "single-node" or "distributed"`,
    };
  }
  return { mode: raw, error: null };
}

/**
 * Replica count for the illegal-topology assertion (multiInstanceGuard.js).
 * Kubernetes gives a pod no built-in way to learn its own Deployment/
 * StatefulSet spec.replicas value (see multiInstanceGuard.js's header
 * comment) — this is an explicit operator acknowledgment, the same class of
 * variable as the existing QODIQA_K8S_SINGLE_REPLICA. Defaults to 1 so the
 * overwhelmingly common single-replica case never false-positives. An
 * operator who already set QODIQA_K8S_SINGLE_REPLICA=true does not need to
 * also state QODIQA_REPLICA_COUNT=1 in a second vocabulary.
 *
 * A malformed value (not a clean positive integer string) falls back to the
 * safe default of 1 rather than failing startup — unlike an invalid
 * QODIQA_DEPLOYMENT_MODE, a bad replica count degrades to "assume the
 * common case", not "silently run in a state nobody chose" — but that
 * fallback is never silent: `warning` carries a human-readable explanation
 * for the caller to surface, so the operator still sees why their intended
 * value was ignored instead of finding out only when the illegal-topology
 * guard behaves differently than expected.
 *
 * @returns {{ value: number, warning: string|null }}
 */
function _resolveReplicaCount(env) {
  const raw = env.QODIQA_REPLICA_COUNT;
  if (raw === undefined || raw === '') return { value: 1, warning: null };

  const n = parseInt(raw, 10);
  // String(n) === raw rejects not just NaN/non-positive but also inputs
  // parseInt would otherwise silently truncate/accept (e.g. "3.7" -> 3,
  // "3abc" -> 3, " 3" -> 3) — any of those indicate a malformed value that
  // happens to parse, not a clean, intentional integer.
  if (Number.isFinite(n) && n > 0 && String(n) === raw) {
    return { value: n, warning: null };
  }
  return {
    value: 1,
    warning: `QODIQA_REPLICA_COUNT is set to an invalid value "${raw}" (must be a positive integer) — falling back to 1. If this deployment actually runs more than one replica, the illegal-topology assertion cannot protect it until this is fixed.`,
  };
}

/**
 * QODIQA_PG_AUTO_MIGRATE, validated the same way: a malformed value falls
 * back to the safe default (disabled — never silently auto-apply schema
 * changes on a typo) but is never silently ignored; `warning` carries the
 * explanation.
 *
 * @returns {{ value: boolean, warning: string|null }}
 */
function _resolveAutoMigrateEnabled(env) {
  const raw = env.QODIQA_PG_AUTO_MIGRATE;
  if (raw === undefined || raw === '') return { value: false, warning: null };
  if (raw === 'true')  return { value: true,  warning: null };
  if (raw === 'false') return { value: false, warning: null };
  return {
    value: false,
    warning: `QODIQA_PG_AUTO_MIGRATE is set to an unrecognized value "${raw}" (must be exactly "true" or "false") — falling back to disabled. Distributed mode will fail closed with AUDIT_CHAIN_MIGRATION_MISSING instead of auto-applying a pending migration.`,
  };
}

let _cached = null;

/**
 * Pure(-ish) resolution of the effective deployment configuration.
 *
 * Memoization applies ONLY to the implicit default-argument call form —
 * getResolvedDeploymentConfig() called with no argument at all, which is
 * exactly how every real production call site invokes it (multiInstanceGuard.js's
 * module-level ORDERING_MODE constant, its _config default parameters, and
 * server/startup.js's DEPLOYMENT_MODE_RESOLVED logging). That call form is
 * memoized per process for the reason documented in the module header: it
 * must observe one single, consistent resolution for the lifetime of the
 * process, regardless of how many times or from how many modules it is
 * called.
 *
 * A call that passes an EXPLICIT env argument — real production code never
 * does this; only tests and other programmatic callers do — always resolves
 * fresh and never reads or writes the memo. This is deliberate: a caller
 * that hands in its own env object is explicitly asking "what would this
 * environment resolve to right now", not "give me the process's one
 * authoritative answer" — silently handing back a stale answer from a
 * previous, unrelated env object would be a correctness bug in that caller's
 * favor, not a performance optimization. (Before this fix, a second call
 * with a different explicit env object silently returned the FIRST call's
 * cached result — see git history / remediation for the incident
 * that caught this.) _resetForTests() remains available to reset the
 * memoized default-path result between test cases that legitimately need to
 * exercise it (e.g. multiInstanceGuard.js's module-load-time resolution).
 *
 * @param {NodeJS.ProcessEnv} [env] — omit to use (and memoize) process.env;
 *   pass explicitly to always resolve fresh, unmemoized.
 * @returns {{
 *   deploymentMode: 'single-node'|'distributed'|null,
 *   source: 'explicit'|'legacy'|'invalid',
 *   error: string|null,
 *   pgEnabled: boolean,
 *   auditOrderingMode: 'single-node'|'distributed',
 *   migrationVerificationRequired: boolean,
 *   autoMigrateEnabled: boolean,
 *   replicaCount: number,
 * }}
 */
function getResolvedDeploymentConfig(env = process.env) {
  // Reference equality, not "was an argument passed" — applyDeploymentMode()
  // (below) has its own `env = process.env` default parameter, so by the
  // time it calls this function env is never literally `undefined`, even on
  // the fully-implicit production call path (applyDeploymentMode() with no
  // arguments). Checking identity against the live process.env object
  // correctly recognizes "this resolves the one ambient environment" in
  // both cases — direct call with no argument, and indirect call through a
  // wrapper that also defaults to process.env — while any distinct object
  // (what every test passes) always takes the unmemoized path below.
  const usingAmbientEnv = env === process.env;
  if (usingAmbientEnv && _cached) return _cached;

  const { mode, error } = resolveDeploymentMode(env);
  const { value: replicaCount,      warning: replicaCountWarning }      = _resolveReplicaCount(env);
  const { value: autoMigrateEnabled, warning: autoMigrateWarning }      = _resolveAutoMigrateEnabled(env);

  if (replicaCountWarning) writeDiagnostic('WARN', 'DEPLOYMENT_MODE_REPLICA_COUNT_INVALID', { reason: replicaCountWarning });
  if (autoMigrateWarning)  writeDiagnostic('WARN', 'DEPLOYMENT_MODE_AUTO_MIGRATE_INVALID',   { reason: autoMigrateWarning });

  let resolved;
  if (error) {
    // Invalid value. applyDeploymentMode() is responsible for failing
    // startup; a safe legacy-equivalent shape is still returned so nothing
    // that reads this before the process actually exits crashes on
    // undefined fields (matters for tests that inject a no-op _exit).
    resolved = {
      deploymentMode: null,
      source: 'invalid',
      error,
      pgEnabled: env.QODIQA_PG_ENABLED === 'true',
      auditOrderingMode: env.QODIQA_AUDIT_ORDERING_MODE === 'distributed' ? 'distributed' : 'single-node',
      migrationVerificationRequired: false,
      autoMigrateEnabled,
      replicaCount,
    };
  } else if (mode === 'distributed') {
    resolved = {
      deploymentMode: 'distributed',
      source: 'explicit',
      error: null,
      pgEnabled: true,
      auditOrderingMode: 'distributed',
      migrationVerificationRequired: true,
      autoMigrateEnabled,
      replicaCount,
    };
  } else if (mode === 'single-node') {
    resolved = {
      deploymentMode: 'single-node',
      source: 'explicit',
      error: null,
      pgEnabled: env.QODIQA_PG_ENABLED === 'true',
      auditOrderingMode: 'single-node',
      migrationVerificationRequired: false,
      autoMigrateEnabled,
      replicaCount,
    };
  } else {
    // Legacy path — QODIQA_DEPLOYMENT_MODE unset. Behavior identical to
    // every release before this module existed.
    const legacyOrdering = env.QODIQA_AUDIT_ORDERING_MODE === 'distributed' ? 'distributed' : 'single-node';
    resolved = {
      deploymentMode: null,
      source: 'legacy',
      error: null,
      pgEnabled: env.QODIQA_PG_ENABLED === 'true',
      auditOrderingMode: legacyOrdering,
      migrationVerificationRequired: legacyOrdering === 'distributed',
      autoMigrateEnabled,
      replicaCount,
    };
  }

  resolved = Object.freeze(resolved);
  if (usingAmbientEnv) _cached = resolved;
  return resolved;
}

// ── Integration ───────────────────────────────────────────────────────────

/**
 * Resolves deployment mode and, when QODIQA_DEPLOYMENT_MODE is explicitly
 * set, normalizes QODIQA_PG_ENABLED / QODIQA_AUDIT_ORDERING_MODE in `env` to
 * the resolved effective values — see the module header for why. No-op on
 * the two legacy vars when QODIQA_DEPLOYMENT_MODE is unset (fully legacy
 * behavior). FATAL-exits (via the same fail-safe stderr diagnostic path
 * src/core/audit/multiInstanceGuard.js uses — this runs even earlier in the
 * startup sequence than that guard, before services/logger's emit() has any
 * business being relied on) if QODIQA_DEPLOYMENT_MODE is set to an
 * unrecognized value.
 *
 * @param {NodeJS.ProcessEnv} env
 * @param {object}  [opts]
 * @param {function} [opts._exit] — injectable for testing (default: process.exit)
 * @returns {ReturnType<typeof getResolvedDeploymentConfig>}
 */
function applyDeploymentMode(env = process.env, { _exit = (code) => process.exit(code) } = {}) {
  const config = getResolvedDeploymentConfig(env);

  if (config.error) {
    writeDiagnostic('FATAL', 'DEPLOYMENT_MODE_INVALID', {
      reason: config.error,
      action: 'Set QODIQA_DEPLOYMENT_MODE to "single-node" or "distributed", or unset it entirely to use legacy QODIQA_PG_ENABLED / QODIQA_AUDIT_ORDERING_MODE configuration.',
      ref: ADR_REF,
    });
    notifyCriticalStartupFailure({
      eventType: 'DEPLOYMENT_MODE_INVALID',
      reason: config.error,
      action: 'Set QODIQA_DEPLOYMENT_MODE to "single-node" or "distributed".',
      deploymentMode: null,
    }).catch(() => {});
    _exit(1);
    return config;
  }

  if (config.deploymentMode) {
    env.QODIQA_PG_ENABLED = config.pgEnabled ? 'true' : 'false';
    env.QODIQA_AUDIT_ORDERING_MODE = config.auditOrderingMode;
  }

  return config;
}

/** Test-only: clears the memoized resolution. */
function _resetForTests() {
  _cached = null;
}

module.exports = {
  resolveDeploymentMode,
  getResolvedDeploymentConfig,
  applyDeploymentMode,
  _resetForTests,
};
