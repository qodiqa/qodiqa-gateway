'use strict';

// a router mounted without requirePermission fails CLOSED outside unit tests.
const { permissionGuard } = require('../permissionGuard');

describe('permissionGuard', () => {
  const saved = process.env.NODE_ENV;
  afterEach(() => { process.env.NODE_ENV = saved; });

  test('uses the injected requirePermission when present', () => {
    const mw = () => {};
    const rp = jest.fn(() => mw);
    expect(permissionGuard(rp, 'READ_WEBHOOKS', 'webhooks')).toBe(mw);
    expect(rp).toHaveBeenCalledWith('READ_WEBHOOKS');
  });

  test.each(['production', 'development'])('NODE_ENV=%s without requirePermission → throws at mount time', (env) => {
    process.env.NODE_ENV = env;
    expect(() => permissionGuard(undefined, 'MANAGE_WEBHOOKS', 'webhooks')).toThrow(/webhooks: requirePermission is required .*MANAGE_WEBHOOKS/);
  });

  test('NODE_ENV=test without requirePermission → pass-through (unit suites mount routers bare)', () => {
    process.env.NODE_ENV = 'test';
    const next = jest.fn();
    permissionGuard(undefined, 'READ_AUDIT', 'auditStore')({}, {}, next);
    expect(next).toHaveBeenCalled();
  });
});
