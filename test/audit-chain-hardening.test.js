'use strict';

/**
 * Component #11 — Audit Chain Architecture Finalization
 *
 * ACH-01  Single instance (no NODE_APP_INSTANCE) is allowed
 * ACH-02  NODE_APP_INSTANCE=0 is allowed (PM2 primary)
 * ACH-03  NODE_APP_INSTANCE=1 triggers FATAL + exit(1)
 * ACH-04  NODE_APP_INSTANCE=2 triggers FATAL + exit(1)
 * ACH-05  cluster.isWorker=true triggers FATAL + exit(1)
 * ACH-06  FATAL event name is AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN
 * ACH-07  FATAL payload includes reason and action fields
 * ACH-08  AUDIT_PG_SYNC_LAG emitted when file exceeds PG by > threshold
 * ACH-09  AUDIT_PG_SYNC_LAG NOT emitted when lag is within threshold
 * ACH-10  AUDIT_PG_UNAVAILABLE emitted on first PG query failure
 * ACH-11  AUDIT_PG_UNAVAILABLE NOT re-emitted on repeated failures
 * ACH-12  AUDIT_PG_RECOVERED emitted when PG becomes reachable again
 * ACH-13  No event emitted on repeated PG availability (steady state)
 * ACH-14  ADR document exists at docs/protocol/AUDIT-SCHEMA-V8.md
 * ACH-15  ADR documents single-node architecture and unsupported deployments
 * ACH-16  ADR documents the distributed-mode Decision Update (SCAL-11)
 * ACH-17  checkDistributedPreconditions: PG disabled triggers FATAL + exit(1)
 * ACH-18  checkDistributedPreconditions: audit_chain_head unreachable triggers FATAL + exit(1)
 * ACH-19  checkDistributedPreconditions: audit_chain_head reachable succeeds, no exit
 * ACH-20  checkStartupPreconditions delegates to checkSingleInstance in single-node mode
 * ACH-21  checkStartupPreconditions delegates to checkDistributedPreconditions in distributed mode
 *
 * SCAL-13 — Kubernetes topology detection (single-node mode)
 * ACH-22  KUBERNETES_SERVICE_HOST set, no ack → FATAL + exit(1)
 * ACH-23  KUBERNETES_SERVICE_HOST set + QODIQA_K8S_SINGLE_REPLICA=true → allowed
 * ACH-24  KUBERNETES_SERVICE_HOST absent → unaffected, allowed
 * ACH-25  FATAL event name is AUDIT_CHAIN_KUBERNETES_TOPOLOGY_UNVERIFIED
 * ACH-26  FATAL payload includes reason, action, and ref fields
 * ACH-27  KUBERNETES_SERVICE_HOST='' (empty string) is not treated as "in Kubernetes"
 * ACH-28  checkStartupPreconditions in distributed mode never reaches the K8s check
 *         even when KUBERNETES_SERVICE_HOST is set (distributed mode is already
 *         replica-count-safe — see distributedOrdering.js)
 */

const fs   = require('fs');
const path = require('path');

// ── Helpers ───────────────────────────────────────────────────────────────────

function capturedStderr(fn) {
  const chunks = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk) => { chunks.push(chunk); return true; };
  try { fn(); } finally { process.stderr.write = orig; }
  return chunks.join('');
}

// ── Modules under test ────────────────────────────────────────────────────────

const {
  checkSingleInstance,
  checkDistributedPreconditions,
  checkStartupPreconditions,
} = require('../src/core/audit/multiInstanceGuard');
const { _checkOnce, _resetState } = require('../src/core/audit/pgLagMonitor');

// ── ACH-01…ACH-07: Multi-Instance Startup Guard ───────────────────────────────

describe('Component #11 — Multi-Instance Startup Guard', () => {

  afterEach(() => { jest.restoreAllMocks(); });

  test('ACH-01 single instance (no NODE_APP_INSTANCE) is allowed', () => {
    const exit = jest.fn();
    // No NODE_APP_INSTANCE in env, not a cluster worker
    checkSingleInstance({ _env: {}, _isWorker: false, _exit: exit });
    expect(exit).not.toHaveBeenCalled();
  });

  test('ACH-02 NODE_APP_INSTANCE=0 (PM2 primary) is allowed', () => {
    const exit = jest.fn();
    checkSingleInstance({ _env: { NODE_APP_INSTANCE: '0' }, _isWorker: false, _exit: exit });
    expect(exit).not.toHaveBeenCalled();
  });

  test('ACH-03 NODE_APP_INSTANCE=1 triggers FATAL and exit(1)', () => {
    const exit = jest.fn();
    let stderrOutput = '';
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => { stderrOutput += chunk; return true; };
    try {
      checkSingleInstance({ _env: { NODE_APP_INSTANCE: '1' }, _isWorker: false, _exit: exit });
    } finally {
      process.stderr.write = orig;
    }
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderrOutput.trim());
    expect(record.severity).toBe('FATAL');
  });

  test('ACH-04 NODE_APP_INSTANCE=2 triggers FATAL and exit(1)', () => {
    const exit = jest.fn();
    checkSingleInstance({ _env: { NODE_APP_INSTANCE: '2' }, _isWorker: false, _exit: exit });
    expect(exit).toHaveBeenCalledWith(1);
  });

  test('ACH-05 cluster.isWorker=true triggers FATAL and exit(1)', () => {
    const exit = jest.fn();
    let stderrOutput = '';
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => { stderrOutput += chunk; return true; };
    try {
      checkSingleInstance({ _env: {}, _isWorker: true, _exit: exit });
    } finally {
      process.stderr.write = orig;
    }
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderrOutput.trim());
    expect(record.severity).toBe('FATAL');
  });

  test('ACH-06 FATAL event name is AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN', () => {
    const exit = jest.fn();
    let stderrOutput = '';
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => { stderrOutput += chunk; return true; };
    try {
      checkSingleInstance({ _env: { NODE_APP_INSTANCE: '1' }, _isWorker: false, _exit: exit });
    } finally {
      process.stderr.write = orig;
    }
    const record = JSON.parse(stderrOutput.trim());
    expect(record.eventType).toBe('AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN');
  });

  test('ACH-07 FATAL payload includes reason, action, and ref fields', () => {
    const exit = jest.fn();
    let stderrOutput = '';
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => { stderrOutput += chunk; return true; };
    try {
      checkSingleInstance({ _env: {}, _isWorker: true, _exit: exit });
    } finally {
      process.stderr.write = orig;
    }
    const record = JSON.parse(stderrOutput.trim());
    expect(typeof record.reason).toBe('string');
    expect(typeof record.action).toBe('string');
    expect(typeof record.ref).toBe('string');
    expect(record.ref).toContain('AUDIT-SCHEMA-V8');
  });

  // ── ACH-22…ACH-27: Kubernetes topology detection (SCAL-13) ─────────────────

  test('ACH-22 KUBERNETES_SERVICE_HOST set, no ack, triggers FATAL and exit(1)', () => {
    const exit = jest.fn();
    checkSingleInstance({
      _env: { KUBERNETES_SERVICE_HOST: '10.0.0.1' },
      _isWorker: false,
      _exit: exit,
    });
    expect(exit).toHaveBeenCalledWith(1);
  });

  test('ACH-23 KUBERNETES_SERVICE_HOST set + QODIQA_K8S_SINGLE_REPLICA=true is allowed', () => {
    const exit = jest.fn();
    checkSingleInstance({
      _env: { KUBERNETES_SERVICE_HOST: '10.0.0.1', QODIQA_K8S_SINGLE_REPLICA: 'true' },
      _isWorker: false,
      _exit: exit,
    });
    expect(exit).not.toHaveBeenCalled();
  });

  test('ACH-24 KUBERNETES_SERVICE_HOST absent is unaffected (existing single-instance behavior)', () => {
    const exit = jest.fn();
    checkSingleInstance({
      _env: { NODE_APP_INSTANCE: '0' },
      _isWorker: false,
      _exit: exit,
    });
    expect(exit).not.toHaveBeenCalled();
  });

  test('ACH-25 FATAL event name is AUDIT_CHAIN_KUBERNETES_TOPOLOGY_UNVERIFIED', () => {
    const exit = jest.fn();
    const record = JSON.parse(capturedStderr(() => {
      checkSingleInstance({ _env: { KUBERNETES_SERVICE_HOST: '10.0.0.1' }, _isWorker: false, _exit: exit });
    }).trim());
    expect(record.eventType).toBe('AUDIT_CHAIN_KUBERNETES_TOPOLOGY_UNVERIFIED');
    expect(record.severity).toBe('FATAL');
  });

  test('ACH-26 FATAL payload includes reason, action, and ref fields', () => {
    const exit = jest.fn();
    const record = JSON.parse(capturedStderr(() => {
      checkSingleInstance({ _env: { KUBERNETES_SERVICE_HOST: '10.0.0.1' }, _isWorker: false, _exit: exit });
    }).trim());
    expect(typeof record.reason).toBe('string');
    expect(typeof record.action).toBe('string');
    expect(record.action).toContain('QODIQA_AUDIT_ORDERING_MODE=distributed');
    expect(record.action).toContain('QODIQA_K8S_SINGLE_REPLICA=true');
    expect(typeof record.ref).toBe('string');
  });

  test("ACH-27 KUBERNETES_SERVICE_HOST='' (empty string) is not treated as in-Kubernetes", () => {
    const exit = jest.fn();
    checkSingleInstance({
      _env: { KUBERNETES_SERVICE_HOST: '' },
      _isWorker: false,
      _exit: exit,
    });
    expect(exit).not.toHaveBeenCalled();
  });

});

// ── ACH-08…ACH-13: PostgreSQL Lag Monitor ─────────────────────────────────────

describe('Component #11 — PG Lag Monitor', () => {

  beforeEach(() => { _resetState(); });

  function makeQueryFn(countOrError) {
    if (countOrError instanceof Error) {
      return () => Promise.reject(countOrError);
    }
    return () => Promise.resolve({ rows: [{ cnt: String(countOrError) }] });
  }

  test('ACH-08 AUDIT_PG_SYNC_LAG emitted when file exceeds PG by more than threshold', async () => {
    const emitted = [];
    await _checkOnce({
      getFileCount: () => 20,
      queryFn:      makeQueryFn(10),
      emitFn:       (level, event, extra) => emitted.push({ level, event, extra }),
      lagThreshold: 5,
    });
    const lag = emitted.find(e => e.event === 'AUDIT_PG_SYNC_LAG');
    expect(lag).toBeDefined();
    expect(lag.level).toBe('WARN');
    expect(lag.extra.lag).toBe(10);
    expect(lag.extra.fileCount).toBe(20);
    expect(lag.extra.pgCount).toBe(10);
  });

  test('ACH-09 AUDIT_PG_SYNC_LAG NOT emitted when lag is within threshold', async () => {
    const emitted = [];
    await _checkOnce({
      getFileCount: () => 10,
      queryFn:      makeQueryFn(8),
      emitFn:       (level, event, extra) => emitted.push({ level, event, extra }),
      lagThreshold: 5,
    });
    expect(emitted.some(e => e.event === 'AUDIT_PG_SYNC_LAG')).toBe(false);
  });

  test('ACH-10 AUDIT_PG_UNAVAILABLE emitted on first PG query failure', async () => {
    const emitted = [];
    const emitFn = (level, event, extra) => emitted.push({ level, event, extra });
    await _checkOnce({
      getFileCount: () => 5,
      queryFn:      makeQueryFn(new Error('connection refused')),
      emitFn,
      lagThreshold: 5,
    });
    const unavail = emitted.find(e => e.event === 'AUDIT_PG_UNAVAILABLE');
    expect(unavail).toBeDefined();
    expect(unavail.level).toBe('WARN');
    expect(unavail.extra.error).toContain('connection refused');
    expect(unavail.extra.fileCount).toBe(5);
  });

  test('ACH-11 AUDIT_PG_UNAVAILABLE NOT re-emitted on repeated failures', async () => {
    const emitted = [];
    const emitFn = (level, event, extra) => emitted.push({ level, event, extra });
    const opts = {
      getFileCount: () => 5,
      queryFn:      makeQueryFn(new Error('timeout')),
      emitFn,
      lagThreshold: 5,
    };
    // First failure: emits UNAVAILABLE
    await _checkOnce(opts);
    // Second failure: must NOT emit again
    await _checkOnce(opts);
    const unavailEvents = emitted.filter(e => e.event === 'AUDIT_PG_UNAVAILABLE');
    expect(unavailEvents).toHaveLength(1);
  });

  test('ACH-12 AUDIT_PG_RECOVERED emitted when PG becomes reachable after outage', async () => {
    const emitted = [];
    const emitFn = (level, event, extra) => emitted.push({ level, event, extra });

    // First call: PG fails → UNAVAILABLE
    await _checkOnce({
      getFileCount: () => 5,
      queryFn:      makeQueryFn(new Error('timeout')),
      emitFn,
      lagThreshold: 5,
    });

    // Second call: PG recovers → RECOVERED
    await _checkOnce({
      getFileCount: () => 5,
      queryFn:      makeQueryFn(5),
      emitFn,
      lagThreshold: 5,
    });

    const recovered = emitted.find(e => e.event === 'AUDIT_PG_RECOVERED');
    expect(recovered).toBeDefined();
    expect(recovered.level).toBe('INFO');
  });

  test('ACH-13 no event emitted in steady state (PG in sync, no prior outage)', async () => {
    const emitted = [];
    const emitFn = (level, event, extra) => emitted.push({ level, event, extra });
    // PG exactly matches file — no lag, no outage
    await _checkOnce({
      getFileCount: () => 100,
      queryFn:      makeQueryFn(100),
      emitFn,
      lagThreshold: 5,
    });
    expect(emitted).toHaveLength(0);
  });

});

describe('Component #11 / SCAL-11 — Distributed-Mode Startup Precondition', () => {

  afterEach(() => { jest.restoreAllMocks(); });

  test('ACH-17 QODIQA_PG_ENABLED not set (pgPool.isEnabled() false) triggers FATAL and exit(1)', async () => {
    const exit   = jest.fn();
    const pgPool = { isEnabled: () => false, query: jest.fn() };
    let stderrOutput = '';
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => { stderrOutput += chunk; return true; };
    try {
      await checkDistributedPreconditions({ _pgPool: pgPool, _exit: exit });
    } finally {
      process.stderr.write = orig;
    }
    expect(exit).toHaveBeenCalledWith(1);
    expect(pgPool.query).not.toHaveBeenCalled();
    const record = JSON.parse(stderrOutput.trim());
    expect(record.severity).toBe('FATAL');
    expect(record.eventType).toBe('AUDIT_CHAIN_DISTRIBUTED_PG_REQUIRED');
  });

  test('ACH-18 audit_chain_head unreachable (query throws) triggers FATAL and exit(1)', async () => {
    const exit   = jest.fn();
    const pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockRejectedValue(new Error('relation "audit_chain_head" does not exist')),
    };
    let stderrOutput = '';
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => { stderrOutput += chunk; return true; };
    try {
      await checkDistributedPreconditions({ _pgPool: pgPool, _exit: exit });
    } finally {
      process.stderr.write = orig;
    }
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderrOutput.trim());
    expect(record.severity).toBe('FATAL');
    expect(record.eventType).toBe('AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE');
  });

  test('ACH-18b audit_chain_head reachable but empty (no seed row) triggers FATAL and exit(1)', async () => {
    const exit   = jest.fn();
    // Label-aware: migration 026 IS recorded (this test is specifically about
    // audit_chain_head's own seed row being missing, a separate
    // precondition — see AUDIT_CHAIN_MIGRATION_MISSING's own dedicated tests
    // in multiInstanceGuard.test.js for the "migration never applied" case).
    const pgPool = {
      isEnabled: () => true,
      query: jest.fn((sql, params, label) =>
        label === 'distributed_migration_verify'
          ? Promise.resolve({ rows: [{ version: 26 }] })
          : Promise.resolve({ rows: [] })
      ),
    };
    const orig = process.stderr.write.bind(process.stderr);
    let stderrOutput = '';
    process.stderr.write = (chunk) => { stderrOutput += chunk; return true; };
    try {
      await checkDistributedPreconditions({ _pgPool: pgPool, _exit: exit });
    } finally {
      process.stderr.write = orig;
    }
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderrOutput.trim());
    expect(record.eventType).toBe('AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE');
  });

  test('ACH-19 audit_chain_head reachable with a seed row succeeds, no exit', async () => {
    const exit   = jest.fn();
    const pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockResolvedValue({ rows: [{ '?column?': 1 }] }),
    };
    const ok = await checkDistributedPreconditions({ _pgPool: pgPool, _exit: exit });
    expect(ok).toBe(true);
    expect(exit).not.toHaveBeenCalled();
    expect(pgPool.query).toHaveBeenCalledWith(
      'SELECT 1 FROM audit_chain_head', [], 'audit_chain_head_probe'
    );
  });

});

// ── ACH-20…ACH-21: Mode-Aware Startup Entry Point ─────────────────────────────

describe('Component #11 / SCAL-11 — checkStartupPreconditions mode dispatch', () => {

  afterEach(() => { jest.restoreAllMocks(); });

  test('ACH-20 single-node mode (default) delegates to checkSingleInstance, no PG involved', async () => {
    // multiInstanceGuard's ORDERING_MODE is computed once at require() time
    // from QODIQA_AUDIT_ORDERING_MODE — this test file's top-level require
    // ran with that env var unset, so checkStartupPreconditions here is
    // already bound to the single-node branch.
    const exit = jest.fn();
    const ok = await checkStartupPreconditions({ _env: {}, _isWorker: false, _exit: exit });
    expect(ok).toBe(true);
    expect(exit).not.toHaveBeenCalled();
  });

  test('ACH-20b single-node mode still blocks multi-instance via checkStartupPreconditions', async () => {
    const exit = jest.fn();
    await checkStartupPreconditions({ _env: { NODE_APP_INSTANCE: '1' }, _isWorker: false, _exit: exit });
    expect(exit).toHaveBeenCalledWith(1);
  });

  test('ACH-21 distributed mode delegates to checkDistributedPreconditions', async () => {
    let capturedResult;
    await jest.isolateModulesAsync(async () => {
      process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
      try {
        const guard = require('../src/core/audit/multiInstanceGuard');
        expect(guard.ORDERING_MODE).toBe('distributed');

        const exit   = jest.fn();
        const pgPool = { isEnabled: () => true, query: jest.fn().mockResolvedValue({ rows: [{ x: 1 }] }) };
        capturedResult = await guard.checkStartupPreconditions({ _pgPool: pgPool, _exit: exit });
        expect(exit).not.toHaveBeenCalled();
        // PM2/cluster fields are accepted but irrelevant in distributed mode —
        // checkSingleInstance's block must never run here.
        expect(pgPool.query).toHaveBeenCalled();
      } finally {
        delete process.env.QODIQA_AUDIT_ORDERING_MODE;
      }
    });
    expect(capturedResult).toBe(true);
  });

  test('ACH-28 distributed mode with KUBERNETES_SERVICE_HOST set never reaches the K8s check ' +
       '(distributed mode is already replica-count-safe)', async () => {
    let capturedResult;
    await jest.isolateModulesAsync(async () => {
      process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
      try {
        const guard  = require('../src/core/audit/multiInstanceGuard');
        const exit   = jest.fn();
        const pgPool = { isEnabled: () => true, query: jest.fn().mockResolvedValue({ rows: [{ x: 1 }] }) };
        // Same env a real K8s pod would have — must NOT trigger the
        // single-node K8s-topology block, because checkStartupPreconditions
        // dispatches straight to checkDistributedPreconditions and never
        // calls checkSingleInstance in this mode.
        capturedResult = await guard.checkStartupPreconditions({
          _env: { KUBERNETES_SERVICE_HOST: '10.0.0.1' },
          _isWorker: false,
          _pgPool: pgPool,
          _exit: exit,
        });
        expect(exit).not.toHaveBeenCalled();
      } finally {
        delete process.env.QODIQA_AUDIT_ORDERING_MODE;
      }
    });
    expect(capturedResult).toBe(true);
  });

});
