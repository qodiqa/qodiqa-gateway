'use strict';

/**
 * Readiness transition tracker — READY-50.
 *
 * GET /ready (src/api/routes/ready.js) calls record() on every probe with the
 * current boolean state of each dependency plus the overall outcome. This
 * module is the sole place that turns "current state" into "state change" —
 * logs and metrics only fire on an actual transition, never on every probe
 * hit, so a Kubernetes readinessProbe polling every few seconds cannot spam
 * the log stream or inflate counters. See docs/deployment/kubernetes-probes.md.
 *
 * Pure in-memory, synchronous, no I/O — safe to call on every request. Never
 * throws: a failure here must not affect the readiness response itself.
 */

const { emit } = require('../../services/logger');
const metrics  = require('../observability/metrics');

const _lastComponentState = new Map(); // component -> boolean|undefined (unset)
const _downSince          = new Map(); // component -> timestamp ms
let _lastOverallState = null;          // boolean|null (null = not yet observed)

/**
 * Record the current health of a single named dependency. Emits a structured
 * log and increments the relevant counter only when the value differs from
 * the last observed value for that component — repeated probes reporting an
 * unchanged state never spam logs or inflate transition counters.
 *
 * @param {string}  component  Fixed, bounded label — e.g. 'persistenceStore'
 * @param {boolean} healthy
 */
function recordComponent(component, healthy) {
  try {
    metrics.readinessComponentUp.set({ component }, healthy ? 1 : 0);

    const prev = _lastComponentState.get(component);
    if (prev === healthy) return;
    const wasUnset = prev === undefined;
    _lastComponentState.set(component, healthy);

    if (healthy) {
      const downSince  = _downSince.get(component);
      const downtimeMs = downSince != null ? Date.now() - downSince : 0;
      _downSince.delete(component);
      metrics.readinessDependencyRecoveryTotal.inc({ component });
      metrics.readinessDependencyDowntimeMs.observe({ component }, downtimeMs);
      if (!wasUnset) {
        emit('INFO', 'READINESS_DEPENDENCY_RECOVERED', { component, downtimeMs });
      }
    } else {
      _downSince.set(component, Date.now());
      metrics.readinessDependencyFailuresTotal.inc({ component });
      // The first observation after process start is the normal
      // pre-startup state, not a runtime failure — log at INFO so startup
      // does not look like an incident to log-based alerting.
      emit(wasUnset ? 'INFO' : 'WARN', 'READINESS_DEPENDENCY_LOST', { component });
    }
  } catch { /* readiness instrumentation must never affect the readiness response */ }
}

/**
 * Record the overall /ready outcome. Emits a structured log and increments
 * the transition counter only on an actual change from the last observed
 * overall state.
 *
 * @param {boolean} ready
 */
function recordOverall(ready) {
  try {
    metrics.readinessState.set({}, ready ? 1 : 0);

    if (_lastOverallState === ready) return;
    const wasUnset = _lastOverallState === null;
    _lastOverallState = ready;

    metrics.readinessTransitionsTotal.inc({ to: ready ? 'ready' : 'not_ready' });

    if (ready) {
      emit('INFO', 'READINESS_RECOVERED', {});
    } else {
      // Startup begins not-ready by design (readinessState.js) — the first
      // observation is expected, not an incident.
      emit(wasUnset ? 'INFO' : 'WARN', 'READINESS_LOST', {});
    }
  } catch { /* readiness instrumentation must never affect the readiness response */ }
}

/** Reset all tracked state. Test-only. */
function _reset() {
  _lastComponentState.clear();
  _downSince.clear();
  _lastOverallState = null;
}

module.exports = { recordComponent, recordOverall, _reset };
