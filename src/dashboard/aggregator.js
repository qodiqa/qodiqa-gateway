'use strict';

/**
 * Dashboard aggregator — public facade over the DashboardRepository.
 *
 * Production flow (no chain scans after startup):
 *   • AggregationStore is initialized once from the full chain at module-load time.
 *   • All subsequent updates arrive via the DashboardBus ('audit.allow' /
 *     'audit.block') and are applied in O(1) inside the store.
 *   • Every read function calls _sync() which is a no-op when _dirty is false.
 *
 * Test flow (backward-compatible with existing test suite):
 *   • invalidate() sets _dirty = true.
 *   • The NEXT read call triggers _sync() → repository.reinitialize() → full
 *     rescan of the mock chain.  This matches the old TTL-cache miss behaviour
 *     so existing tests that push to STUB_CHAIN then call invalidate() work
 *     without modification.
 *   • A read call without a preceding invalidate() returns the stored state —
 *     exactly the "cache hit" expectation tested by "caches the result".
 *
 * All exported function signatures and return shapes are preserved exactly
 * so that src/api/routes/dashboard.js and all existing tests require zero
 * changes.
 */

const repository = require('./repository');

// ── Dirty flag ────────────────────────────────────────────────────────────────
// false  = store is current (bus events keep it up-to-date)
// true   = store must be re-synced before the next read
//
// Starts false: store/index.js already ran initialize() at module load.
let _dirty = false;

function _sync() {
  if (!_dirty) return;
  repository.reinitialize();
  _dirty = false;
}

// ── Public API ────────────────────────────────────────────────────────────────

function getAggregates() {
  _sync();
  return {
    overview:       repository.getOverview(),
    executions:     repository.getAll('executions'),
    blocked:        repository.getAll('blocked'),
    replays:        repository.getAll('replays'),
    anomalies:      repository.getAll('anomalies'),
    activitySeries: repository.getActivity().series,
    byAnomalyType:  repository.getAnomalies().byType,
  };
}

function getOverview()    { _sync(); return repository.getOverview(); }
function getExecutions(o) { _sync(); return repository.getExecutions(o); }
function getBlocked(o)    { _sync(); return repository.getBlocked(o); }
function getReplays(o)    { _sync(); return repository.getReplays(o); }
function getAnomalies(o)  { _sync(); return repository.getAnomalies(o); }
function getActivity(o)   { _sync(); return repository.getActivity(o); }

/**
 * Mark state as dirty so the next read triggers repository.reinitialize().
 *
 * Test use only.  In production the store is kept current by the bus;
 * this function is never called.
 */
function invalidate() { _dirty = true; }

module.exports = {
  getAggregates,
  getOverview,
  getExecutions,
  getBlocked,
  getReplays,
  getAnomalies,
  getActivity,
  invalidate,
};
