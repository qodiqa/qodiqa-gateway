'use strict';

/**
 * First test coverage for src/core/audit/multiInstanceGuard.js, added
 * alongside MON-3's best-effort CRITICAL notification hook.
 *
 * The key property under test (see earlyCriticalNotify.js's header comment
 * and the MON-3 plan): the guard's fatal exit must stay synchronous and
 * immediate — _exit() is asserted to have already been called by the time
 * checkSingleInstance() *returns*, before any awaiting happens on the mocked
 * notify call, proving the notification cannot delay or gate the exit.
 */

jest.mock('../../../runtime/rawStderrDiagnostic', () => ({
  writeDiagnostic: jest.fn(),
}));
jest.mock('../../../runtime/earlyCriticalNotify', () => ({
  notifyCriticalStartupFailure: jest.fn(),
}));

const { writeDiagnostic } = require('../../../runtime/rawStderrDiagnostic');
const { notifyCriticalStartupFailure } = require('../../../runtime/earlyCriticalNotify');

describe('multiInstanceGuard — checkSingleInstance', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Resolve on a later microtask so we can prove _exit already fired
    // synchronously, before this promise had any chance to settle.
    notifyCriticalStartupFailure.mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 5)));
  });

  function load() {
    jest.resetModules();
    jest.doMock('../../../runtime/rawStderrDiagnostic', () => ({ writeDiagnostic }));
    jest.doMock('../../../runtime/earlyCriticalNotify', () => ({ notifyCriticalStartupFailure }));
    return require('../multiInstanceGuard');
  }

  test('no violation: clean single-node env does not exit or notify', () => {
    const { checkSingleInstance } = load();
    const _exit = jest.fn();
    checkSingleInstance({ _env: {}, _isWorker: false, _exit });

    expect(_exit).not.toHaveBeenCalled();
    expect(writeDiagnostic).not.toHaveBeenCalled();
    expect(notifyCriticalStartupFailure).not.toHaveBeenCalled();
  });

  test('PM2 non-zero instance: writes FATAL diagnostic, notifies, and exits(1) synchronously', () => {
    const { checkSingleInstance } = load();
    const _exit = jest.fn();
    checkSingleInstance({ _env: { NODE_APP_INSTANCE: '1' }, _isWorker: false, _exit });

    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN', expect.objectContaining({ NODE_APP_INSTANCE: '1' })
    );
    // The critical property: _exit already happened by the time this
    // synchronous call returns — not after the (still-pending) notify promise.
    expect(_exit).toHaveBeenCalledWith(1);
    expect(notifyCriticalStartupFailure).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN', deploymentMode: 'single-node' })
    );
  });

  test('PM2 instance "0" is allowed (primary instance)', () => {
    const { checkSingleInstance } = load();
    const _exit = jest.fn();
    checkSingleInstance({ _env: { NODE_APP_INSTANCE: '0' }, _isWorker: false, _exit });

    expect(_exit).not.toHaveBeenCalled();
    expect(notifyCriticalStartupFailure).not.toHaveBeenCalled();
  });

  test('Node cluster worker: writes FATAL diagnostic, notifies, and exits(1)', () => {
    const { checkSingleInstance } = load();
    const _exit = jest.fn();
    checkSingleInstance({ _env: {}, _isWorker: true, _exit });

    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN', expect.any(Object)
    );
    expect(_exit).toHaveBeenCalledWith(1);
    expect(notifyCriticalStartupFailure).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN' })
    );
  });

  test('Kubernetes topology without single-replica ack: exits(1) and notifies', () => {
    const { checkSingleInstance } = load();
    const _exit = jest.fn();
    checkSingleInstance({
      _env: { KUBERNETES_SERVICE_HOST: '10.0.0.1' }, _isWorker: false, _exit,
    });

    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_KUBERNETES_TOPOLOGY_UNVERIFIED', expect.any(Object)
    );
    expect(_exit).toHaveBeenCalledWith(1);
    expect(notifyCriticalStartupFailure).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'AUDIT_CHAIN_KUBERNETES_TOPOLOGY_UNVERIFIED' })
    );
  });

  test('Kubernetes topology WITH single-replica ack: no violation', () => {
    const { checkSingleInstance } = load();
    const _exit = jest.fn();
    checkSingleInstance({
      _env: { KUBERNETES_SERVICE_HOST: '10.0.0.1', QODIQA_K8S_SINGLE_REPLICA: 'true' },
      _isWorker: false, _exit,
    });

    expect(_exit).not.toHaveBeenCalled();
    expect(notifyCriticalStartupFailure).not.toHaveBeenCalled();
  });

  test('notify rejection never surfaces — exit already happened regardless', async () => {
    notifyCriticalStartupFailure.mockImplementation(() => Promise.reject(new Error('network down')));
    const { checkSingleInstance } = load();
    const _exit = jest.fn();

    expect(() => {
      checkSingleInstance({ _env: { NODE_APP_INSTANCE: '1' }, _isWorker: false, _exit });
    }).not.toThrow();
    expect(_exit).toHaveBeenCalledWith(1);

    // Let the rejected promise's microtask settle — must not produce an
    // unhandled rejection or throw back into the test.
    await new Promise((resolve) => setImmediate(resolve));
  });
});

describe('multiInstanceGuard — checkDistributedPreconditions', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    notifyCriticalStartupFailure.mockResolvedValue(undefined);
  });

  function load() {
    jest.resetModules();
    jest.doMock('../../../runtime/rawStderrDiagnostic', () => ({ writeDiagnostic }));
    jest.doMock('../../../runtime/earlyCriticalNotify', () => ({ notifyCriticalStartupFailure }));
    return require('../multiInstanceGuard');
  }

  test('PG disabled: exits(1) and notifies with distributed deploymentMode', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = { isEnabled: () => false };

    const result = await checkDistributedPreconditions({ _pgPool, _exit });

    expect(result).toBe(false);
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_DISTRIBUTED_PG_REQUIRED', expect.any(Object)
    );
    expect(_exit).toHaveBeenCalledWith(1);
    expect(notifyCriticalStartupFailure).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'AUDIT_CHAIN_DISTRIBUTED_PG_REQUIRED' })
    );
  });

  test('audit_chain_head unreachable: exits(1) and notifies', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockRejectedValue(new Error('connection refused')),
    };

    const result = await checkDistributedPreconditions({ _pgPool, _exit });

    expect(result).toBe(false);
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE', expect.any(Object)
    );
    expect(_exit).toHaveBeenCalledWith(1);
    expect(notifyCriticalStartupFailure).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE' })
    );
  });

  test('healthy PG: no exit, no notify', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockResolvedValue({ rows: [{ ok: 1 }] }),
    };

    const result = await checkDistributedPreconditions({ _pgPool, _exit });

    expect(result).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
    expect(notifyCriticalStartupFailure).not.toHaveBeenCalled();
  });

  // ── migration 026 verification + auto-migrate ─────────────────────

  function _pgPoolWithMigrationState({ migrationApplied, afterMigrateApplied = true, runMigrations }) {
    let migrated = false;
    return {
      isEnabled: () => true,
      query: jest.fn((sql, params, label) => {
        if (label === 'distributed_migration_verify') {
          const applied = migrated ? afterMigrateApplied : migrationApplied;
          return Promise.resolve({ rows: applied ? [{ version: 26 }] : [] });
        }
        // audit_chain_head probe — only reached once migration is confirmed applied.
        return Promise.resolve({ rows: [{ tail_hash: 'GENESIS' }] });
      }),
      runMigrations: runMigrations ?? jest.fn().mockImplementation(async () => { migrated = true; }),
    };
  }

  test('migration 026 missing, auto-migrate disabled: FATAL AUDIT_CHAIN_MIGRATION_MISSING, exit(1)', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = _pgPoolWithMigrationState({ migrationApplied: false });
    const _config = { autoMigrateEnabled: false };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(false);
    expect(_pgPool.runMigrations).not.toHaveBeenCalled();
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_MIGRATION_MISSING',
      expect.objectContaining({ expectedMigration: 26, autoMigrateAttempted: false })
    );
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('migration 026 missing, auto-migrate enabled: runs migrations, re-verifies, succeeds', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = _pgPoolWithMigrationState({ migrationApplied: false, afterMigrateApplied: true });
    const _config = { autoMigrateEnabled: true };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(true);
    expect(_pgPool.runMigrations).toHaveBeenCalled();
    expect(_exit).not.toHaveBeenCalled();
    expect(writeDiagnostic).not.toHaveBeenCalled();
  });

  test('migration 026 still missing after auto-migrate: FATAL AUDIT_CHAIN_MIGRATION_MISSING with autoMigrateAttempted:true', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = _pgPoolWithMigrationState({ migrationApplied: false, afterMigrateApplied: false });
    const _config = { autoMigrateEnabled: true };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(false);
    expect(_pgPool.runMigrations).toHaveBeenCalled();
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_MIGRATION_MISSING',
      expect.objectContaining({ autoMigrateAttempted: true })
    );
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('auto-migrate throws: FATAL AUDIT_CHAIN_AUTO_MIGRATE_FAILED, exit(1)', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = _pgPoolWithMigrationState({
      migrationApplied: false,
      runMigrations: jest.fn().mockRejectedValue(new Error('permission denied for table qodiqa_migrations')),
    });
    const _config = { autoMigrateEnabled: true };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(false);
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_AUTO_MIGRATE_FAILED',
      expect.objectContaining({ reason: expect.stringContaining('permission denied') })
    );
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('virgin database (qodiqa_migrations relation does not exist, 42P01) with auto-migrate enabled: bootstraps and succeeds', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    let migrated = false;
    const _pgPool = {
      isEnabled: () => true,
      query: jest.fn((sql, params, label) => {
        if (label === 'distributed_migration_verify') {
          if (!migrated) {
            const err = new Error('relation "qodiqa_migrations" does not exist');
            err.code = '42P01';
            return Promise.reject(err);
          }
          return Promise.resolve({ rows: [{ version: 26 }] });
        }
        return Promise.resolve({ rows: [{ tail_hash: 'GENESIS' }] });
      }),
      runMigrations: jest.fn().mockImplementation(async () => { migrated = true; }),
    };
    const _config = { autoMigrateEnabled: true };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(true);
    expect(_pgPool.runMigrations).toHaveBeenCalled();
    expect(_exit).not.toHaveBeenCalled();
    expect(writeDiagnostic).not.toHaveBeenCalled();
  });

  test('virgin database (42P01), auto-migrate disabled: FATAL AUDIT_CHAIN_MIGRATION_MISSING (not PG_UNREACHABLE)', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const err = new Error('relation "qodiqa_migrations" does not exist');
    err.code = '42P01';
    const _pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockRejectedValue(err),
      runMigrations: jest.fn(),
    };
    const _config = { autoMigrateEnabled: false };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(false);
    expect(_pgPool.runMigrations).not.toHaveBeenCalled();
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_MIGRATION_MISSING', expect.any(Object)
    );
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('migration query itself fails (connectivity): FATAL AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE, never attempts auto-migrate', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockRejectedValue(new Error('connection refused')),
      runMigrations: jest.fn(),
    };
    const _config = { autoMigrateEnabled: true };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(false);
    expect(_pgPool.runMigrations).not.toHaveBeenCalled();
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE', expect.any(Object)
    );
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('circuit breaker open (PG_CIRCUIT_OPEN) is reported distinctly from generic unreachability (finding #3)', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const circuitOpenErr = new Error('PostgreSQL circuit breaker is OPEN — fast-failing without contacting the database');
    circuitOpenErr.code = 'PG_CIRCUIT_OPEN';
    const _pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockRejectedValue(circuitOpenErr),
      runMigrations: jest.fn(),
    };
    const _config = { autoMigrateEnabled: true };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(false);
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE',
      expect.objectContaining({
        circuitBreakerOpen: true,
        reason: expect.stringContaining('circuit breaker is currently OPEN'),
      })
    );
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('a plain connectivity error is reported with circuitBreakerOpen:false', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = {
      isEnabled: () => true,
      query: jest.fn().mockRejectedValue(new Error('connection refused')),
      runMigrations: jest.fn(),
    };
    const _config = { autoMigrateEnabled: false };

    await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_DISTRIBUTED_PG_UNREACHABLE',
      expect.objectContaining({ circuitBreakerOpen: false })
    );
  });

  test('migration already applied: skips auto-migrate entirely even when enabled', async () => {
    const { checkDistributedPreconditions } = load();
    const _exit = jest.fn();
    const _pgPool = _pgPoolWithMigrationState({ migrationApplied: true });
    const _config = { autoMigrateEnabled: true };

    const result = await checkDistributedPreconditions({ _pgPool, _config, _exit });

    expect(result).toBe(true);
    expect(_pgPool.runMigrations).not.toHaveBeenCalled();
    expect(_exit).not.toHaveBeenCalled();
  });
});

describe('multiInstanceGuard — assertNoIllegalTopology', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    notifyCriticalStartupFailure.mockResolvedValue(undefined);
  });

  function load() {
    jest.resetModules();
    jest.doMock('../../../runtime/rawStderrDiagnostic', () => ({ writeDiagnostic }));
    jest.doMock('../../../runtime/earlyCriticalNotify', () => ({ notifyCriticalStartupFailure }));
    return require('../multiInstanceGuard');
  }

  test('PG enabled + single-node ordering + replicaCount > 1: FATAL AUDIT_CHAIN_ILLEGAL_TOPOLOGY, exit(1)', () => {
    const { assertNoIllegalTopology } = load();
    const _exit = jest.fn();
    const _pgPool = { isEnabled: () => true };
    const _config = { replicaCount: 2 };

    const ok = assertNoIllegalTopology({ _pgPool, _config, _exit });

    expect(ok).toBe(false);
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'AUDIT_CHAIN_ILLEGAL_TOPOLOGY',
      expect.objectContaining({
        detectedTopology: expect.objectContaining({ pgEnabled: true, orderingMode: 'single-node', replicaCount: 2 }),
      })
    );
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('PG enabled + replicaCount > 1 but replicaCount is exactly 1: no violation', () => {
    const { assertNoIllegalTopology } = load();
    const _exit = jest.fn();
    const _pgPool = { isEnabled: () => true };
    const _config = { replicaCount: 1 };

    const ok = assertNoIllegalTopology({ _pgPool, _config, _exit });

    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
  });

  test('PG disabled + replicaCount > 1: no violation (the common multi-replica file-only topology)', () => {
    const { assertNoIllegalTopology } = load();
    const _exit = jest.fn();
    const _pgPool = { isEnabled: () => false };
    const _config = { replicaCount: 2 };

    const ok = assertNoIllegalTopology({ _pgPool, _config, _exit });

    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
  });

  test('PG enabled + replicaCount > 1 but ordering already distributed: no violation', () => {
    jest.resetModules();
    process.env.QODIQA_DEPLOYMENT_MODE = 'distributed';
    jest.doMock('../../../runtime/rawStderrDiagnostic', () => ({ writeDiagnostic }));
    jest.doMock('../../../runtime/earlyCriticalNotify', () => ({ notifyCriticalStartupFailure }));
    try {
      const { assertNoIllegalTopology } = require('../multiInstanceGuard');
      const _exit = jest.fn();
      const _pgPool = { isEnabled: () => true };
      const _config = { replicaCount: 5 };

      const ok = assertNoIllegalTopology({ _pgPool, _config, _exit });

      expect(ok).toBe(true);
      expect(_exit).not.toHaveBeenCalled();
    } finally {
      delete process.env.QODIQA_DEPLOYMENT_MODE;
    }
  });
});

describe('multiInstanceGuard — ORDERING_MODE resolution via deploymentMode resolver', () => {
  afterEach(() => {
    delete process.env.QODIQA_DEPLOYMENT_MODE;
    delete process.env.QODIQA_AUDIT_ORDERING_MODE;
  });

  test('QODIQA_DEPLOYMENT_MODE=distributed resolves ORDERING_MODE=distributed with no QODIQA_AUDIT_ORDERING_MODE set', () => {
    jest.resetModules();
    process.env.QODIQA_DEPLOYMENT_MODE = 'distributed';
    const guard = require('../multiInstanceGuard');
    expect(guard.ORDERING_MODE).toBe('distributed');
  });

  test('QODIQA_DEPLOYMENT_MODE=single-node resolves ORDERING_MODE=single-node even if legacy var says distributed', () => {
    jest.resetModules();
    process.env.QODIQA_DEPLOYMENT_MODE = 'single-node';
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
    const guard = require('../multiInstanceGuard');
    expect(guard.ORDERING_MODE).toBe('single-node');
  });

  test('QODIQA_DEPLOYMENT_MODE unset falls through to legacy QODIQA_AUDIT_ORDERING_MODE (unchanged behavior)', () => {
    jest.resetModules();
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
    const guard = require('../multiInstanceGuard');
    expect(guard.ORDERING_MODE).toBe('distributed');
  });
});
