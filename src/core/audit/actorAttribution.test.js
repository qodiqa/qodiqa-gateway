'use strict';

/**
 * AUTH-3 remediation — canonical actor-attribution helper tests.
 *
 * Proves resolveOperatorActor() derives the audit actor from req.rbacUser
 * (the identity opsAuth + rbacResolve actually populate), never silently
 * defaults an authenticated request to "system", and reports the rare
 * misconfiguration case (no rbacUser at all) loudly instead of quietly.
 */

const mockEmit = jest.fn();
jest.mock('../../../services/logger', () => ({ emit: mockEmit }));

const {
  resolveOperatorActor,
  SYSTEM_ACTOR,
  UNATTRIBUTED_OPERATOR,
  AUDIT_ATTRIBUTION_FAILED,
} = require('./actorAttribution');

beforeEach(() => jest.clearAllMocks());

describe('resolveOperatorActor', () => {
  test('AA-01 returns rbacUser.username when present', () => {
    const req = { rbacUser: { id: 'u1', username: 'alice', role: 'admin' } };
    expect(resolveOperatorActor(req)).toBe('alice');
    expect(mockEmit).not.toHaveBeenCalled();
  });

  test('AA-02 falls back to rbacUser.id when username is absent', () => {
    const req = { rbacUser: { id: 'u2', role: 'admin' } };
    expect(resolveOperatorActor(req)).toBe('u2');
    expect(mockEmit).not.toHaveBeenCalled();
  });

  test('AA-03 never returns "system" for an authenticated request', () => {
    const req = { rbacUser: { id: 'u3', username: 'bob', role: 'operator' } };
    expect(resolveOperatorActor(req)).not.toBe(SYSTEM_ACTOR);
  });

  test('AA-04 missing rbacUser: returns UNATTRIBUTED_OPERATOR, not "system"', () => {
    const req = { path: '/v1/admin/organizations', method: 'POST', requestId: 'r-1' };
    const actor = resolveOperatorActor(req);
    expect(actor).toBe(UNATTRIBUTED_OPERATOR);
    expect(actor).not.toBe(SYSTEM_ACTOR);
  });

  test('AA-05 missing rbacUser emits AUDIT_ATTRIBUTION_FAILED with request context', () => {
    const req = { path: '/v1/admin/tenants', method: 'PATCH', requestId: 'r-2' };
    resolveOperatorActor(req);
    expect(mockEmit).toHaveBeenCalledWith('WARN', AUDIT_ATTRIBUTION_FAILED, expect.objectContaining({
      path: '/v1/admin/tenants', method: 'PATCH', requestId: 'r-2',
    }));
  });

  test('AA-06 empty rbacUser object (no username/id) is treated as unattributed', () => {
    const req = { rbacUser: {}, path: '/x', method: 'GET', requestId: null };
    expect(resolveOperatorActor(req)).toBe(UNATTRIBUTED_OPERATOR);
    expect(mockEmit).toHaveBeenCalledWith('WARN', AUDIT_ATTRIBUTION_FAILED, expect.any(Object));
  });

  test('AA-07 null req does not throw and is treated as unattributed', () => {
    expect(resolveOperatorActor(null)).toBe(UNATTRIBUTED_OPERATOR);
    expect(resolveOperatorActor(undefined)).toBe(UNATTRIBUTED_OPERATOR);
  });

  test('AA-08 SYSTEM_ACTOR and UNATTRIBUTED_OPERATOR are distinct sentinels', () => {
    expect(SYSTEM_ACTOR).not.toBe(UNATTRIBUTED_OPERATOR);
  });

  test('AA-09 rbacUser with only a role (RBAC misassembled) is unattributed, not "system"', () => {
    const req = { rbacUser: { role: 'admin' } };
    expect(resolveOperatorActor(req)).toBe(UNATTRIBUTED_OPERATOR);
  });

  test('AA-10 frozen rbacUser (as attached by opsAuth) resolves normally', () => {
    const req = { rbacUser: Object.freeze({ id: 'u4', username: 'carol', role: 'admin', enabled: true }) };
    expect(resolveOperatorActor(req)).toBe('carol');
  });
});
