'use strict';

jest.mock('../../runtime/rawStderrDiagnostic', () => ({
  writeDiagnostic: jest.fn(),
}));
jest.mock('../../runtime/earlyCriticalNotify', () => ({
  notifyCriticalStartupFailure: jest.fn(),
}));

const { writeDiagnostic } = require('../../runtime/rawStderrDiagnostic');
const { notifyCriticalStartupFailure } = require('../../runtime/earlyCriticalNotify');

const {
  resolveDeploymentMode,
  getResolvedDeploymentConfig,
  applyDeploymentMode,
  _resetForTests,
} = require('./deploymentMode');

beforeEach(() => {
  jest.clearAllMocks();
  notifyCriticalStartupFailure.mockResolvedValue(undefined);
  _resetForTests();
});

describe('resolveDeploymentMode', () => {
  test('unset → null mode, no error', () => {
    expect(resolveDeploymentMode({})).toEqual({ mode: null, error: null });
  });

  test('empty string → treated as unset', () => {
    expect(resolveDeploymentMode({ QODIQA_DEPLOYMENT_MODE: '' })).toEqual({ mode: null, error: null });
  });

  test('"single-node" → resolved', () => {
    expect(resolveDeploymentMode({ QODIQA_DEPLOYMENT_MODE: 'single-node' }))
      .toEqual({ mode: 'single-node', error: null });
  });

  test('"distributed" → resolved', () => {
    expect(resolveDeploymentMode({ QODIQA_DEPLOYMENT_MODE: 'distributed' }))
      .toEqual({ mode: 'distributed', error: null });
  });

  test('unrecognized value → null mode with error', () => {
    const result = resolveDeploymentMode({ QODIQA_DEPLOYMENT_MODE: 'clustered' });
    expect(result.mode).toBeNull();
    expect(result.error).toMatch(/clustered/);
  });
});

describe('getResolvedDeploymentConfig — legacy path (QODIQA_DEPLOYMENT_MODE unset)', () => {
  test('legacy vars fully control pgEnabled/auditOrderingMode, exactly as before this module existed', () => {
    const config = getResolvedDeploymentConfig({
      QODIQA_PG_ENABLED: 'true',
      QODIQA_AUDIT_ORDERING_MODE: 'distributed',
    });

    expect(config).toMatchObject({
      deploymentMode: null,
      source: 'legacy',
      error: null,
      pgEnabled: true,
      auditOrderingMode: 'distributed',
      migrationVerificationRequired: true,
      autoMigrateEnabled: false,
      replicaCount: 1,
    });
  });

  test('legacy vars both absent → single-node, PG disabled (today\'s default)', () => {
    const config = getResolvedDeploymentConfig({});
    expect(config).toMatchObject({
      deploymentMode: null,
      source: 'legacy',
      pgEnabled: false,
      auditOrderingMode: 'single-node',
      migrationVerificationRequired: false,
    });
  });
});

describe('getResolvedDeploymentConfig — explicit distributed mode', () => {
  test('resolves PG enabled + distributed ordering + migration verification, with no other var set', () => {
    const config = getResolvedDeploymentConfig({ QODIQA_DEPLOYMENT_MODE: 'distributed' });
    expect(config).toMatchObject({
      deploymentMode: 'distributed',
      source: 'explicit',
      error: null,
      pgEnabled: true,
      auditOrderingMode: 'distributed',
      migrationVerificationRequired: true,
    });
  });

  test('legacy QODIQA_PG_ENABLED=false is overridden — deployment mode has highest precedence', () => {
    const config = getResolvedDeploymentConfig({
      QODIQA_DEPLOYMENT_MODE: 'distributed',
      QODIQA_PG_ENABLED: 'false',
      QODIQA_AUDIT_ORDERING_MODE: 'single-node',
    });
    expect(config.pgEnabled).toBe(true);
    expect(config.auditOrderingMode).toBe('distributed');
  });

  test('QODIQA_PG_AUTO_MIGRATE=true is surfaced as autoMigrateEnabled', () => {
    const config = getResolvedDeploymentConfig({
      QODIQA_DEPLOYMENT_MODE: 'distributed',
      QODIQA_PG_AUTO_MIGRATE: 'true',
    });
    expect(config.autoMigrateEnabled).toBe(true);
  });
});

describe('getResolvedDeploymentConfig — explicit single-node mode', () => {
  test('forces single-node ordering but still honors legacy QODIQA_PG_ENABLED for the optional PG mirror', () => {
    const config = getResolvedDeploymentConfig({
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      QODIQA_PG_ENABLED: 'true',
      QODIQA_AUDIT_ORDERING_MODE: 'distributed', // must be overridden
    });
    expect(config).toMatchObject({
      deploymentMode: 'single-node',
      auditOrderingMode: 'single-node',
      pgEnabled: true,
      migrationVerificationRequired: false,
    });
  });

  test('PG left disabled by default', () => {
    const config = getResolvedDeploymentConfig({ QODIQA_DEPLOYMENT_MODE: 'single-node' });
    expect(config.pgEnabled).toBe(false);
  });
});

describe('getResolvedDeploymentConfig — replica count resolution', () => {
  test('defaults to 1 when unset', () => {
    expect(getResolvedDeploymentConfig({}).replicaCount).toBe(1);
  });

  test('QODIQA_REPLICA_COUNT is parsed', () => {
    expect(getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: '3' }).replicaCount).toBe(3);
  });

  test('invalid QODIQA_REPLICA_COUNT falls back to 1', () => {
    expect(getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: 'nope' }).replicaCount).toBe(1);
    expect(getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: '0' }).replicaCount).toBe(1);
    expect(getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: '-3' }).replicaCount).toBe(1);
  });

  test('a value that silently truncates (e.g. "3.7", "3abc") is rejected, not silently accepted as 3', () => {
    expect(getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: '3.7' }).replicaCount).toBe(1);
    expect(getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: '3abc' }).replicaCount).toBe(1);
    expect(getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: ' 3' }).replicaCount).toBe(1);
  });

  test('QODIQA_K8S_SINGLE_REPLICA=true alone implies replicaCount 1 without needing the new var', () => {
    // Same effective value as the default, but exercised explicitly since
    // it is the documented interoperability path with the existing var.
    expect(getResolvedDeploymentConfig({ QODIQA_K8S_SINGLE_REPLICA: 'true' }).replicaCount).toBe(1);
  });
});

describe('getResolvedDeploymentConfig — validation diagnostics', () => {
  test('malformed QODIQA_REPLICA_COUNT emits a visible WARN, not a silent fallback', () => {
    getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: 'nope' });
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'WARN', 'DEPLOYMENT_MODE_REPLICA_COUNT_INVALID',
      expect.objectContaining({ reason: expect.stringContaining('nope') })
    );
  });

  test('unset or valid QODIQA_REPLICA_COUNT never warns', () => {
    getResolvedDeploymentConfig({});
    getResolvedDeploymentConfig({ QODIQA_REPLICA_COUNT: '3' });
    expect(writeDiagnostic).not.toHaveBeenCalledWith('WARN', 'DEPLOYMENT_MODE_REPLICA_COUNT_INVALID', expect.anything());
  });

  test('unrecognized QODIQA_PG_AUTO_MIGRATE emits a visible WARN and falls back to disabled', () => {
    const config = getResolvedDeploymentConfig({ QODIQA_PG_AUTO_MIGRATE: 'TRUE' });
    expect(config.autoMigrateEnabled).toBe(false);
    expect(writeDiagnostic).toHaveBeenCalledWith(
      'WARN', 'DEPLOYMENT_MODE_AUTO_MIGRATE_INVALID',
      expect.objectContaining({ reason: expect.stringContaining('TRUE') })
    );
  });

  test('unset, "true", or "false" QODIQA_PG_AUTO_MIGRATE never warns', () => {
    getResolvedDeploymentConfig({});
    getResolvedDeploymentConfig({ QODIQA_PG_AUTO_MIGRATE: 'true' });
    getResolvedDeploymentConfig({ QODIQA_PG_AUTO_MIGRATE: 'false' });
    expect(writeDiagnostic).not.toHaveBeenCalledWith('WARN', 'DEPLOYMENT_MODE_AUTO_MIGRATE_INVALID', expect.anything());
  });
});

describe('getResolvedDeploymentConfig — memoization', () => {
  // Prior to remediation, memoization keyed off "was any argument passed" —
  // a SECOND call with a DIFFERENT explicit env object silently returned the
  // FIRST call's stale cached result with no error or warning. Memoization
  // must apply ONLY to the implicit process.env path (what every real
  // production call site uses); any call that passes its own explicit env
  // object — as every test here does — must always resolve fresh.

  test('two calls with different EXPLICIT env objects never share a cached result', () => {
    const first = getResolvedDeploymentConfig({ QODIQA_DEPLOYMENT_MODE: 'distributed' });
    const second = getResolvedDeploymentConfig({ QODIQA_DEPLOYMENT_MODE: 'single-node' });

    expect(first.deploymentMode).toBe('distributed');
    expect(second.deploymentMode).toBe('single-node');
    expect(second).not.toBe(first);
  });

  test('repeated calls with the SAME explicit env object still resolve independently (no caching side effect)', () => {
    const env = { QODIQA_DEPLOYMENT_MODE: 'distributed' };
    const first = getResolvedDeploymentConfig(env);
    env.QODIQA_DEPLOYMENT_MODE = 'single-node'; // mutate the same object
    const second = getResolvedDeploymentConfig(env);

    expect(first.deploymentMode).toBe('distributed');
    expect(second.deploymentMode).toBe('single-node');
  });

  test('the implicit process.env path (no argument) IS memoized across calls', () => {
    process.env.QODIQA_DEPLOYMENT_MODE = 'distributed';
    try {
      const first = getResolvedDeploymentConfig();
      process.env.QODIQA_DEPLOYMENT_MODE = 'single-node'; // change the real env
      const second = getResolvedDeploymentConfig(); // still no argument

      expect(second).toBe(first); // memoized — did not observe the env change
      expect(second.deploymentMode).toBe('distributed');
    } finally {
      delete process.env.QODIQA_DEPLOYMENT_MODE;
    }
  });

  test('an explicit call to getResolvedDeploymentConfig(process.env) also uses (and populates) the memo', () => {
    process.env.QODIQA_DEPLOYMENT_MODE = 'distributed';
    try {
      const viaDefault  = getResolvedDeploymentConfig();
      const viaExplicit = getResolvedDeploymentConfig(process.env);
      expect(viaExplicit).toBe(viaDefault);
    } finally {
      delete process.env.QODIQA_DEPLOYMENT_MODE;
    }
  });

  test('_resetForTests() clears the memoized ambient-env result', () => {
    process.env.QODIQA_DEPLOYMENT_MODE = 'distributed';
    try {
      const first = getResolvedDeploymentConfig();
      expect(first.deploymentMode).toBe('distributed');

      process.env.QODIQA_DEPLOYMENT_MODE = 'single-node';
      _resetForTests();
      const second = getResolvedDeploymentConfig();
      expect(second.deploymentMode).toBe('single-node');
    } finally {
      delete process.env.QODIQA_DEPLOYMENT_MODE;
    }
  });
});

describe('applyDeploymentMode', () => {
  test('no-op on legacy vars when QODIQA_DEPLOYMENT_MODE is unset', () => {
    const env = { QODIQA_PG_ENABLED: 'true', QODIQA_AUDIT_ORDERING_MODE: 'single-node' };
    const config = applyDeploymentMode(env);

    expect(config.source).toBe('legacy');
    expect(env.QODIQA_PG_ENABLED).toBe('true');
    expect(env.QODIQA_AUDIT_ORDERING_MODE).toBe('single-node');
    expect(writeDiagnostic).not.toHaveBeenCalled();
  });

  test('distributed mode normalizes both legacy vars in place', () => {
    const env = { QODIQA_DEPLOYMENT_MODE: 'distributed' };
    applyDeploymentMode(env);

    expect(env.QODIQA_PG_ENABLED).toBe('true');
    expect(env.QODIQA_AUDIT_ORDERING_MODE).toBe('distributed');
  });

  test('single-node mode normalizes ordering, leaves PG_ENABLED at its resolved (legacy-sourced) value', () => {
    const env = { QODIQA_DEPLOYMENT_MODE: 'single-node', QODIQA_AUDIT_ORDERING_MODE: 'distributed' };
    applyDeploymentMode(env);

    expect(env.QODIQA_AUDIT_ORDERING_MODE).toBe('single-node');
    expect(env.QODIQA_PG_ENABLED).toBe('false');
  });

  test('invalid value: writes FATAL diagnostic, notifies, and exits(1) synchronously — never mutates env', () => {
    const env = { QODIQA_DEPLOYMENT_MODE: 'clustered', QODIQA_PG_ENABLED: 'true' };
    const _exit = jest.fn();

    applyDeploymentMode(env, { _exit });

    expect(writeDiagnostic).toHaveBeenCalledWith(
      'FATAL', 'DEPLOYMENT_MODE_INVALID', expect.objectContaining({ reason: expect.stringContaining('clustered') })
    );
    expect(_exit).toHaveBeenCalledWith(1);
    expect(notifyCriticalStartupFailure).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'DEPLOYMENT_MODE_INVALID' })
    );
    // env must be left completely untouched on the invalid path.
    expect(env.QODIQA_PG_ENABLED).toBe('true');
  });

  test('invalid value: exit already happened before the notify promise settles', async () => {
    notifyCriticalStartupFailure.mockImplementation(() => new Promise((resolve) => setTimeout(resolve, 5)));
    const _exit = jest.fn();

    applyDeploymentMode({ QODIQA_DEPLOYMENT_MODE: 'bogus' }, { _exit });

    expect(_exit).toHaveBeenCalledWith(1);
  });
});
