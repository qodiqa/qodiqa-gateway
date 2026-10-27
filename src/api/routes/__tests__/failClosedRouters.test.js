'use strict';

/**
 * the attestation and verification-portal ADMIN router factories
 * used `requirePermission ? requirePermission('X') : _noop`, so a mount without requirePermission served every admin
 * route permission-free. They now use permissionGuard (fail closed outside NODE_ENV=test).
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { createAttestationAdminRouter } = require('../attestation');
const { createVerificationPortalAdminRouter } = require('../verificationPortal');

const FACTORIES = [
  ['attestationAdmin', createAttestationAdminRouter, ['READ_ATTESTATIONS', 'EXPORT_ATTESTATIONS', 'MANAGE_ATTESTATIONS']],
  ['verificationPortalAdmin', createVerificationPortalAdminRouter, ['READ_VERIFICATION_PORTAL']],
];

describe('admin router factories fail closed without requirePermission', () => {
  const saved = process.env.NODE_ENV;
  afterEach(() => { process.env.NODE_ENV = saved; });

  test.each(FACTORIES)('%s: NODE_ENV=production and no requirePermission → throws at mount time', (name, factory) => {
    process.env.NODE_ENV = 'production';
    expect(() => factory({})).toThrow(new RegExp(`${name}: requirePermission is required`));
    expect(() => factory()).toThrow(/requirePermission is required/);
  });

  test.each(FACTORIES)('%s: NODE_ENV=development and no requirePermission → throws at mount time', (_name, factory) => {
    process.env.NODE_ENV = 'development';
    expect(() => factory({})).toThrow(/requirePermission is required/);
  });

  test.each(FACTORIES)('%s: an injected requirePermission is used for every permission', (_name, factory, perms) => {
    process.env.NODE_ENV = 'production';
    const rp = jest.fn(() => (_q, _s, n) => n());
    factory({ requirePermission: rp });
    expect(rp.mock.calls.map((c) => c[0]).sort()).toEqual([...perms].sort());
  });
});
