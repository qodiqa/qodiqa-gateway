'use strict';

/**
 * InMemoryRepository — DashboardRepository backed by AggregationStore.
 *
 * All data reads are O(1) counter lookups or O(k) bounded-buffer slices
 * where k ≤ retention.maxXxx.  No audit-chain scans occur during
 * normal request handling.
 *
 * Multi-tenant queries:
 *   Pass tenantId to filter entries to a single tenant.  When tenantId is
 *   omitted, all entries are returned (admin view).
 *
 * Pagination:
 *   Entries are returned newest-first.  page=1 is the most-recent page.
 */

class InMemoryRepository {
  constructor(store) {
    this._store = store;
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  reinitialize() {
    this._store.reinitialize();
  }

  // ── Reads ─────────────────────────────────────────────────────────────────

  getOverview() {
    return this._store.getMetrics().getOverview();
  }

  getExecutions({ page = 1, pageSize = 50, tenantId } = {}) {
    const all      = this._store.getExecutions(tenantId).reverse();
    const total    = all.length;
    const start    = (page - 1) * pageSize;
    const entries  = all.slice(start, start + pageSize);
    return { entries, total, page, pageSize };
  }

  getBlocked({ page = 1, pageSize = 50, tenantId } = {}) {
    const all     = this._store.getBlocked(tenantId).reverse();
    const byReason = this._store.getMetrics().getByReason();
    const total   = all.length;
    const start   = (page - 1) * pageSize;
    const entries = all.slice(start, start + pageSize);
    return { entries, total, page, pageSize, byReason };
  }

  getReplays({ page = 1, pageSize = 50, tenantId } = {}) {
    const all     = this._store.getReplays(tenantId).reverse();
    const total   = all.length;
    const start   = (page - 1) * pageSize;
    const entries = all.slice(start, start + pageSize);
    return { entries, total, page, pageSize };
  }

  getAnomalies({ page = 1, pageSize = 50, tenantId } = {}) {
    const all     = this._store.getAnomalies(tenantId).reverse();
    const byType  = this._store.getMetrics().getByAnomalyType();
    const total   = all.length;
    const start   = (page - 1) * pageSize;
    const entries = all.slice(start, start + pageSize);
    return { entries, total, page, pageSize, byType };
  }

  getActivity({ windowMinutes = 60 } = {}) {
    const series = this._store.getMetrics().getTimeBuckets(windowMinutes);
    return { series, windowMinutes };
  }

  /**
   * Return all entries for a category (no pagination) — used by getAggregates().
   * Returns a copy of the bounded buffer, oldest-first.
   *
   * @param {'executions'|'blocked'|'replays'|'anomalies'} category
   */
  getAll(category) {
    switch (category) {
      case 'executions': return this._store.getExecutions();
      case 'blocked':    return this._store.getBlocked();
      case 'replays':    return this._store.getReplays();
      case 'anomalies':  return this._store.getAnomalies();
      default:           return [];
    }
  }
}

module.exports = { InMemoryRepository };
