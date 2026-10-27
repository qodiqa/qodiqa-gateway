'use strict';

/**
 * Startup Retention Privilege Validation Tests —
 *
 * RT-PRIV-01 … RT-PRIV-02  PG disabled / happy path
 * RT-PRIV-03               Query shape: has_table_privilege probes issued for
 *                          every required grant, in order
 * RT-PRIV-04 … RT-PRIV-06  Missing table privilege (UPDATE / DELETE / INSERT
 *                          on audit_retention_runs) fails closed
 * RT-PRIV-07 … RT-PRIV-08  Missing/misconfigured RLS policy (UPDATE / DELETE)
 *                          fails closed
 * RT-PRIV-09               Role reported from QODIQA_PG_RETENTION_USER in
 *                          the failure diagnostic
 * RT-PRIV-10               No _exit call when the check passes
 *
 * All PG interaction is injected via _retentionPool (a fake with just
 * isEnabled()/query()) — this module's public function accepts
 * _retentionPool/_metrics/_exit/_emit/_now, mirroring
 * mirrorConsistencyCheck.js's testable design.
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { verifyRetentionPrivileges } = require('../retentionPrivilegeCheck');

const ALL_PRIVILEGES_GRANTED = [
  { table: 'platform_audit_events',    privilege: 'SELECT' },
  { table: 'platform_audit_events',    privilege: 'UPDATE' },
  { table: 'platform_audit_events',    privilege: 'DELETE' },
  { table: 'audit_retention_policies', privilege: 'SELECT' },
  { table: 'audit_retention_runs',     privilege: 'SELECT' },
  { table: 'audit_retention_runs',     privilege: 'INSERT' },
  // step 6 (migration 069): request_trails under OPERATIONAL retention
  { table: 'request_trails',           privilege: 'SELECT' },
  { table: 'request_trails',           privilege: 'UPDATE' },
  { table: 'request_trails',           privilege: 'DELETE' },
];
const ALL_POLICIES_PRESENT = [
  { table: 'platform_audit_events', policy: 'pae_retention_select', cmd: 'SELECT' },
  { table: 'platform_audit_events', policy: 'pae_retention_update', cmd: 'UPDATE' },
  { table: 'platform_audit_events', policy: 'pae_retention_delete', cmd: 'DELETE' },
  // arp_retention_select (migration 054) — without it,
  // audit_retention_policies has zero applicable RLS policy for
  // qodiqa_retention and every SELECT it runs silently returns 0 rows.
  { table: 'audit_retention_policies', policy: 'arp_retention_select', cmd: 'SELECT' },
  { table: 'request_trails', policy: 'rt_retention_select', cmd: 'SELECT' },
  { table: 'request_trails', policy: 'rt_retention_update', cmd: 'UPDATE' },
  { table: 'request_trails', policy: 'rt_retention_delete', cmd: 'DELETE' },
];

function makeMetrics() {
  return {
    auditRetentionPrivilegeCheckSuccessTotal: { inc: jest.fn() },
    auditRetentionPrivilegeCheckFailureTotal: { inc: jest.fn() },
    auditRetentionPrivilegeCheckDurationSeconds: { observe: jest.fn() },
  };
}

/**
 * Fake retentionPool.query(): routes has_table_privilege probes (5 calls, in
 * the fixed order the implementation issues them) and pg_policies probes (2
 * calls) to caller-supplied grant/policy sets, so tests can express "this
 * one grant/policy is missing" declaratively rather than mocking call order.
 */
function makeFakeRetentionPool({
  enabled = true,
  grantedPrivileges = ALL_PRIVILEGES_GRANTED,
  presentPolicies = ALL_POLICIES_PRESENT,
} = {}) {
  const calls = [];
  const query = jest.fn(async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes('has_table_privilege')) {
      const [table, privilege] = params;
      const granted = grantedPrivileges.some(p => p.table === table && p.privilege === privilege);
      return { rows: [{ granted }] };
    }
    if (sql.includes('pg_policies')) {
      const [table, policy, cmd, role] = params;
      const present = presentPolicies.some(
        p => p.table === table && p.policy === policy && p.cmd === cmd,
      );
      return { rows: present ? [{ '?column?': 1 }] : [] };
    }
    throw new Error(`unexpected query in test fake: ${sql}`);
  });
  return { isEnabled: () => enabled, query, __calls: calls };
}

beforeEach(() => {
  delete process.env.QODIQA_PG_RETENTION_USER;
});

describe('RT-PRIV-01 … RT-PRIV-02: skip and success paths', () => {
  test('RT-PRIV-01 returns true and skips entirely when the retention pool is disabled', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const _retentionPool = makeFakeRetentionPool({ enabled: false });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
    expect(_metrics.auditRetentionPrivilegeCheckSuccessTotal.inc).not.toHaveBeenCalled();
  });

  test('RT-PRIV-02 returns true when every grant and RLS policy is present', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const _emit = jest.fn();
    const _retentionPool = makeFakeRetentionPool();

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit });

    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
    expect(_metrics.auditRetentionPrivilegeCheckSuccessTotal.inc).toHaveBeenCalledWith({});
    expect(_metrics.auditRetentionPrivilegeCheckDurationSeconds.observe).toHaveBeenCalled();
    expect(_emit).toHaveBeenCalledWith('INFO', 'AUDIT_RETENTION_PRIVILEGE_CHECK_PASSED', expect.any(Object));
  });
});

describe('RT-PRIV-03: query shape', () => {
  test('probes has_table_privilege for every required grant and pg_policies for every required policy', async () => {
    const _retentionPool = makeFakeRetentionPool();

    await verifyRetentionPrivileges({ _retentionPool, _metrics: makeMetrics(), _exit: jest.fn(), _emit: jest.fn() });

    const privilegeCalls = _retentionPool.__calls.filter(c => c.sql.includes('has_table_privilege'));
    const policyCalls    = _retentionPool.__calls.filter(c => c.sql.includes('pg_policies'));

    expect(privilegeCalls).toHaveLength(ALL_PRIVILEGES_GRANTED.length);
    expect(privilegeCalls.map(c => c.params)).toEqual(
      ALL_PRIVILEGES_GRANTED.map(p => [p.table, p.privilege]),
    );
    expect(policyCalls).toHaveLength(ALL_POLICIES_PRESENT.length);
  });
});

describe('RT-PRIV-04 … RT-PRIV-06: missing table privilege fails closed', () => {
  test('RT-PRIV-04 missing UPDATE on platform_audit_events', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const grantedPrivileges = ALL_PRIVILEGES_GRANTED.filter(
      p => !(p.table === 'platform_audit_events' && p.privilege === 'UPDATE'),
    );
    const _retentionPool = makeFakeRetentionPool({ grantedPrivileges });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'UPDATE' });
  });

  test('RT-PRIV-05 missing DELETE on platform_audit_events', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const grantedPrivileges = ALL_PRIVILEGES_GRANTED.filter(
      p => !(p.table === 'platform_audit_events' && p.privilege === 'DELETE'),
    );
    const _retentionPool = makeFakeRetentionPool({ grantedPrivileges });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'DELETE' });
  });

  test('RT-PRIV-12 missing DELETE on request_trails', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const grantedPrivileges = ALL_PRIVILEGES_GRANTED.filter(p => !(p.table === 'request_trails' && p.privilege === 'DELETE'));
    const _retentionPool = makeFakeRetentionPool({ grantedPrivileges });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'DELETE' });
  });

  test('RT-PRIV-13 rt_retention_delete policy absent', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const presentPolicies = ALL_POLICIES_PRESENT.filter(p => p.policy !== 'rt_retention_delete');
    const _retentionPool = makeFakeRetentionPool({ presentPolicies });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'DELETE' });
  });

  test('RT-PRIV-06 missing INSERT on audit_retention_runs (journaling would fail)', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const grantedPrivileges = ALL_PRIVILEGES_GRANTED.filter(
      p => !(p.table === 'audit_retention_runs' && p.privilege === 'INSERT'),
    );
    const _retentionPool = makeFakeRetentionPool({ grantedPrivileges });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'INSERT' });
  });
});

describe('RT-PRIV-07 … RT-PRIV-08: missing/misconfigured RLS policy fails closed', () => {
  test('RT-PRIV-07a pae_retention_select policy absent (UPDATE/DELETE would silently affect 0 rows without it)', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const presentPolicies = ALL_POLICIES_PRESENT.filter(p => p.policy !== 'pae_retention_select');
    const _retentionPool = makeFakeRetentionPool({ presentPolicies });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'SELECT' });
  });

  test('RT-PRIV-07 pae_retention_update policy absent', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const presentPolicies = ALL_POLICIES_PRESENT.filter(p => p.policy !== 'pae_retention_update');
    const _retentionPool = makeFakeRetentionPool({ presentPolicies });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'UPDATE' });
  });

  test('RT-PRIV-08 pae_retention_delete policy absent (e.g. qual altered away from unconditional true)', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const presentPolicies = ALL_POLICIES_PRESENT.filter(p => p.policy !== 'pae_retention_delete');
    const _retentionPool = makeFakeRetentionPool({ presentPolicies });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'DELETE' });
  });

  // positive/negative coverage for arp_retention_select (migration
  // 054) — before this item, the gate never checked for this policy at all,
  // so it could not have caught either its absence (this test) or a future
  // regression that accidentally drops it. See D4.
  test('RT-PRIV-11 arp_retention_select policy absent (stampRetentionDates() would silently see 0 policy rows)', async () => {
    const _exit = jest.fn();
    const _metrics = makeMetrics();
    const presentPolicies = ALL_POLICIES_PRESENT.filter(p => p.policy !== 'arp_retention_select');
    const _retentionPool = makeFakeRetentionPool({ presentPolicies });

    const ok = await verifyRetentionPrivileges({ _retentionPool, _metrics, _exit, _emit: jest.fn() });

    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
    expect(_metrics.auditRetentionPrivilegeCheckFailureTotal.inc).toHaveBeenCalledWith({ operation: 'SELECT' });
  });
});

describe('RT-PRIV-09 … RT-PRIV-10: fail-closed wiring and diagnostics', () => {
  test('RT-PRIV-09 reports the QODIQA_PG_RETENTION_USER role in the failure diagnostic', async () => {
    process.env.QODIQA_PG_RETENTION_USER = 'custom_retention_role';
    const stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const grantedPrivileges = ALL_PRIVILEGES_GRANTED.filter(
        p => !(p.table === 'platform_audit_events' && p.privilege === 'UPDATE'),
      );
      const _retentionPool = makeFakeRetentionPool({ grantedPrivileges });

      await verifyRetentionPrivileges({ _retentionPool, _metrics: makeMetrics(), _exit: jest.fn(), _emit: jest.fn() });

      const written = stderrSpy.mock.calls.map(c => c[0]).join('\n');
      expect(written).toContain('custom_retention_role');
      expect(written).toContain('AUDIT_RETENTION_PRIVILEGE_CHECK_FAILED');
    } finally {
      stderrSpy.mockRestore();
    }
  });

  test('RT-PRIV-10 does not call _exit when the check passes', async () => {
    const _exit = jest.fn();
    const _retentionPool = makeFakeRetentionPool();

    await verifyRetentionPrivileges({ _retentionPool, _metrics: makeMetrics(), _exit, _emit: jest.fn() });

    expect(_exit).not.toHaveBeenCalled();
  });
});
