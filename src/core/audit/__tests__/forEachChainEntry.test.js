'use strict';

/**
 * — audit-log.forEachChainEntry(): the bounded-memory, snapshot-consistent walk the dashboard's
 * boot aggregation now uses instead of materialising the history with getAuditChain(). Real audit-log in file mode,
 * a small in-memory window so the walk takes the durable (file) path.
 *
 *   FE-1  same entries, same order as getAuditChain(); count == getChainLength()
 *   FE-2  the event loop runs between pages (a setImmediate callback fires before the walk ends)
 *   FE-3  snapshot: entries appended DURING the walk are not visited (they reach consumers through their live path)
 *   FE-4  the dashboard AggregationStore ends in the identical state via initializeFromIterator and via the previous
 *         initialize(getAuditChain)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../entryBuilder');

const fields = (i) => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: i % 5 === 0 ? 'BLOCK' : 'ALLOW',
  outputHash: EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
  verificationResult: i % 5 !== 0, tenantId: `t-${i % 3}`, executionContext: i % 5 === 0 ? { reason: i % 10 === 0 ? 'REPLAY_DETECTED' : 'POLICY_DENY' } : undefined });

describe('forEachChainEntry', () => {
  let dir; let auditLog;
  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut08-'));
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    process.env.QODIQA_AUDIT_WINDOW_SIZE = '20';
    jest.resetModules();
    auditLog = require('../audit-log');
    for (let i = 0; i < 120; i++) await auditLog.append(fields(i));
  });
  afterEach(() => {
    delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
    jest.resetModules();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('FE-1 same entries in the same order as getAuditChain()', async () => {
    const full = (await auditLog.getAuditChain()).map((e) => e.hash);
    const walked = [];
    const n = await auditLog.forEachChainEntry((e) => walked.push(e.hash), { pageSize: 7 });
    expect(n).toBe(auditLog.getChainLength());
    expect(walked).toEqual(full);
    expect(walked).toHaveLength(120);
  });

  test('FE-2 the event loop runs between pages', async () => {
    let ticked = false; let visitedAtTick = null; let visited = 0;
    setImmediate(() => { ticked = true; visitedAtTick = visited; });
    await auditLog.forEachChainEntry(() => { visited++; }, { pageSize: 10 });
    expect(ticked).toBe(true);
    expect(visitedAtTick).toBeGreaterThan(0);
    expect(visitedAtTick).toBeLessThan(120);
  });

  test('FE-3 entries appended during the walk are not visited', async () => {
    const before = auditLog.getChainLength();
    const appended = [];
    let triggered = false;
    const n = await auditLog.forEachChainEntry(() => {
      if (!triggered) { triggered = true; appended.push(auditLog.append(fields(1)), auditLog.append(fields(2))); }
    }, { pageSize: 10 });
    await Promise.all(appended);
    expect(n).toBe(before);
    expect(auditLog.getChainLength()).toBe(before + 2);
  });

  test('FE-5 getModernHashesAt returns exactly what getModernEntryAt returns, in one pass', async () => {
    const n = auditLog.getChainLength();
    const positions = [0, 3, 57, 99, 100, 119, n - 1, 57, 5000, -1, 2.5]; // inside/outside the 20-entry window, dup, out of range
    const many = await auditLog.getModernHashesAt(positions);
    for (const p of positions) {
      const one = await auditLog.getModernEntryAt(p);
      if (one) expect(many.get(p)).toBe(one.hash);
      else expect(many.has(p)).toBe(false);
    }
    expect(many.size).toBe(new Set(positions.filter((p) => Number.isInteger(p) && p >= 0 && p < n)).size);
  });

  test('FE-4 the dashboard store reaches the identical state through both initialisers', async () => {
    const { AggregationStore } = require('../../../dashboard/store/AggregationStore');
    const { MetricsEngine } = require('../../../dashboard/metrics/MetricsEngine');
    const retention = require('../../../dashboard/retention');
    const bus = { subscribe: () => {} };
    const a = new AggregationStore(bus, new MetricsEngine(retention), retention);
    const b = new AggregationStore(bus, new MetricsEngine(retention), retention);
    await a.initialize(auditLog.getAuditChain);
    const visited = await b.initializeFromIterator(auditLog.forEachChainEntry);
    expect(visited).toBe(120);
    const snap = (s) => JSON.stringify({ o: s.getMetrics().getOverview(), c: s.getMetrics().getCounters(), r0: s.getMetrics().getByReason(),
      tn: s.getMetrics().getByTenant(), tb: s.getMetrics().getTimeBuckets(1e6),
      e: s.getExecutions(), b: s.getBlocked(), r: s.getReplays(), an: s.getAnomalies(), t0: s.getExecutions('t-0') });
    expect(snap(b)).toEqual(snap(a));
    expect(a.getExecutions().length).toBeGreaterThan(0);
    expect(a.getReplays().length).toBeGreaterThan(0);
  });
});
