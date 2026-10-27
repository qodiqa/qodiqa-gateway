'use strict';

/**
 * (matrix row 40) — a change of a user's role is audited: the RBAC store emits RBAC_USER_UPDATED carrying the new role and the
 * actor, and the central store classifies RBAC_* and SIGNING_IDENTITY_ADMIN_* as ACCESS_CONTROL events.
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit } = require('../../../../services/logger');
const store = require('../store');
const { classifyEventType } = require('../../audit/centralStore');

describe('privilege-change audit (matrix row 40)', () => {
  test('PC-01 a role change emits RBAC_USER_UPDATED with the new role and the actor', () => {
    const u = store.createUser({ username: `pc-user-${Date.now()}`, role: 'viewer' });
    emit.mockClear();
    store.updateUser(u.id, { role: 'operator', updatedBy: 'pc-admin' });
    const call = emit.mock.calls.find((c) => c[1] === 'RBAC_USER_UPDATED');
    expect(call).toBeTruthy();
    expect(call[2]).toMatchObject({ userId: u.id, updatedBy: 'pc-admin', changes: { role: 'operator' } });
  });

  test('PC-02 user, role and signing-identity privilege events are all ACCESS_CONTROL', () => {
    for (const t of ['RBAC_USER_CREATED', 'RBAC_USER_UPDATED', 'RBAC_USER_DELETED', 'SIGNING_IDENTITY_ADMIN_CREATED', 'SIGNING_IDENTITY_ADMIN_UPDATED']) {
      expect(classifyEventType(t)).toBe('ACCESS_CONTROL');
    }
  });
});
