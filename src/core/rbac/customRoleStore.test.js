'use strict';

/**
 * RBAC Custom Role Store — test suite
 *
 * CR-01…CR-10  Role creation and validation
 * CR-11…CR-18  Permission validation (unknown / duplicate / structure)
 * CR-19…CR-25  Update / delete / list
 * CR-26…CR-32  Authorization composition (authorize.js)
 * CR-33…CR-38  Persistence / serialization
 * CR-39…CR-44  Backward compatibility with built-in roles
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { ROLES, PERMISSION_SET, isPermitted: canonicalIsPermitted } = require('./roles');

function freshCustomRoleStore() {
  const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-custom-role-test-'));
  const tmpPath = path.join(tmpDir, 'rbac-custom-roles.json');
  process.env.QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH = tmpPath;
  jest.resetModules();
  const customRoleStore = require('./customRoleStore');
  customRoleStore._reset();
  return { customRoleStore, tmpPath };
}

// Resets the module registry ONCE and requires both stores together, so
// store.js's own internal `require('./customRoleStore')` resolves to the
// exact same fresh instance this helper returns — requiring them via two
// separate reset cycles would leave store.js bound to a stale, orphaned
// customRoleStore instance instead.
function freshLinkedStores() {
  const userTmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-user-store-test-'));
  const roleTmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-custom-role-test-'));
  process.env.QODIQA_RBAC_STORE_PATH             = path.join(userTmpDir, 'rbac-users.json');
  process.env.QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH = path.join(roleTmpDir, 'rbac-custom-roles.json');
  jest.resetModules();
  const customRoleStore = require('./customRoleStore');
  const store           = require('./store');
  customRoleStore._reset();
  store._reset();
  return { store, customRoleStore };
}

const SOME_PERMS = ['READ_POLICIES', 'REVIEW_POLICY_CHANGE'];

describe('CR-01…CR-10  Role creation and validation', () => {
  test('CR-01  creates a custom role with a "custom:" namespaced ID derived from name', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS, createdBy: 'admin1' });
    expect(role.id).toBe('custom:policy-reviewer');
    expect(role.name).toBe('Policy Reviewer');
    expect(role.permissions).toEqual(SOME_PERMS);
    expect(role.enabled).toBe(true);
    expect(role.builtIn).toBe(false);
    expect(role.createdBy).toBe('admin1');
  });

  test('CR-02  rejects a name that is empty, too short, or invalid', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.createRole({ name: '', permissions: SOME_PERMS }))
      .toThrow(customRoleStore.CustomRoleStoreError);
    expect(() => customRoleStore.createRole({ name: 'a', permissions: SOME_PERMS }))
      .toThrow(customRoleStore.CustomRoleStoreError);
  });

  test('CR-03  rejects a name that collides with a reserved built-in role', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.createRole({ name: 'admin', permissions: SOME_PERMS }))
      .toThrow(/reserved/i);
    for (const canonical of Object.values(ROLES)) {
      expect(() => customRoleStore.createRole({ name: canonical, permissions: SOME_PERMS }))
        .toThrow(customRoleStore.CustomRoleStoreError);
    }
  });

  test('CR-04  rejects creating a role whose slug already exists', () => {
    const { customRoleStore } = freshCustomRoleStore();
    customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS });
    expect(() => customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS }))
      .toThrow(/already exists/i);
  });

  test('CR-05  two different names that slugify to the same ID are treated as the same role', () => {
    const { customRoleStore } = freshCustomRoleStore();
    customRoleStore.createRole({ name: 'Policy  Reviewer', permissions: SOME_PERMS });
    // "Policy Reviewer" (single space) slugifies identically to "Policy  Reviewer" (double space)
    expect(() => customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS }))
      .toThrow(/already exists/i);
  });

  test('CR-06  createdRole.permissions is frozen (no runtime mutation)', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Frozen Test', permissions: SOME_PERMS });
    expect(Object.isFrozen(role.permissions)).toBe(true);
  });

  test('CR-07  description defaults to empty string when omitted', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'No Description', permissions: SOME_PERMS });
    expect(role.description).toBe('');
  });

  test('CR-08  isCustomRoleId distinguishes custom role IDs from canonical role strings', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(customRoleStore.isCustomRoleId('custom:policy-reviewer')).toBe(true);
    expect(customRoleStore.isCustomRoleId('admin')).toBe(false);
    expect(customRoleStore.isCustomRoleId('')).toBe(false);
    expect(customRoleStore.isCustomRoleId(null)).toBe(false);
    expect(customRoleStore.isCustomRoleId(undefined)).toBe(false);
    expect(customRoleStore.isCustomRoleId(42)).toBe(false);
  });

  test('CR-09  getRole returns null for a non-"custom:" ID (never confused with a built-in role)', () => {
    const { customRoleStore } = freshCustomRoleStore();
    customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS });
    expect(customRoleStore.getRole('admin')).toBeNull();
    expect(customRoleStore.getRole('policy-reviewer')).toBeNull(); // missing prefix
  });

  test('CR-10  getRole returns null for an unknown custom role ID', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(customRoleStore.getRole('custom:does-not-exist')).toBeNull();
  });
});

describe('CR-11…CR-18  Permission validation', () => {
  test('CR-11  rejects a non-array permissions value', () => {
    const { customRoleStore } = freshCustomRoleStore();
    for (const bad of ['READ_POLICIES', null, undefined, {}, 42]) {
      expect(() => customRoleStore.validatePermissionsList(bad))
        .toThrow(expect.objectContaining({ code: 'INVALID_PERMISSIONS_STRUCTURE' }));
    }
  });

  test('CR-12  rejects an empty permissions array', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.validatePermissionsList([]))
      .toThrow(expect.objectContaining({ code: 'EMPTY_PERMISSIONS' }));
  });

  test('CR-13  rejects a non-string / empty-string entry', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.validatePermissionsList(['READ_POLICIES', 42]))
      .toThrow(expect.objectContaining({ code: 'INVALID_PERMISSIONS_STRUCTURE' }));
    expect(() => customRoleStore.validatePermissionsList(['READ_POLICIES', '']))
      .toThrow(expect.objectContaining({ code: 'INVALID_PERMISSIONS_STRUCTURE' }));
  });

  test('CR-14  rejects unknown permission names', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.validatePermissionsList(['READ_POLICIES', 'NOT_A_REAL_PERMISSION']))
      .toThrow(expect.objectContaining({ code: 'UNKNOWN_PERMISSION', details: { unknown: ['NOT_A_REAL_PERMISSION'] } }));
  });

  test('CR-15  rejects duplicate permission names', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.validatePermissionsList(['READ_POLICIES', 'READ_POLICIES']))
      .toThrow(expect.objectContaining({ code: 'DUPLICATE_PERMISSION', details: { duplicates: ['READ_POLICIES'] } }));
  });

  test('CR-16  accepts every real permission individually', () => {
    const { customRoleStore } = freshCustomRoleStore();
    for (const perm of PERMISSION_SET) {
      expect(customRoleStore.validatePermissionsList([perm])).toEqual([perm]);
    }
  });

  test('CR-17  createRole propagates permission validation errors — no role is persisted on failure', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.createRole({ name: 'Bad Role', permissions: ['NOT_REAL'] }))
      .toThrow(expect.objectContaining({ code: 'UNKNOWN_PERMISSION' }));
    expect(customRoleStore.listRoles()).toHaveLength(0);
  });

  test('CR-18  updateRole propagates permission validation errors — original permissions are untouched', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Good Role', permissions: SOME_PERMS });
    expect(() => customRoleStore.updateRole(role.id, { permissions: ['NOT_REAL'] }))
      .toThrow(expect.objectContaining({ code: 'UNKNOWN_PERMISSION' }));
    expect(customRoleStore.getRole(role.id).permissions).toEqual(SOME_PERMS);
  });
});

describe('CR-19…CR-25  Update / delete / list', () => {
  test('CR-19  updateRole replaces the permission set and updates updatedAt/updatedBy', async () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Reviewer', permissions: SOME_PERMS, createdBy: 'admin1' });
    await new Promise(r => setTimeout(r, 5));
    const updated = customRoleStore.updateRole(role.id, { permissions: ['MANAGE_WEBHOOKS'], updatedBy: 'admin2' });
    expect(updated.permissions).toEqual(['MANAGE_WEBHOOKS']);
    expect(updated.updatedBy).toBe('admin2');
    expect(updated.updatedAt).not.toBe(role.updatedAt);
  });

  test('CR-20  renaming a role never changes its ID', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Reviewer', permissions: SOME_PERMS });
    const renamed = customRoleStore.updateRole(role.id, { name: 'Senior Reviewer' });
    expect(renamed.id).toBe(role.id);
    expect(renamed.name).toBe('Senior Reviewer');
  });

  test('CR-21  updateRole on an unknown ID throws NOT_FOUND', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.updateRole('custom:nope', { name: 'X' }))
      .toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
  });

  test('CR-22  disabling a role via updateRole keeps the role but flips enabled', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Reviewer', permissions: SOME_PERMS });
    const disabled = customRoleStore.updateRole(role.id, { enabled: false });
    expect(disabled.enabled).toBe(false);
    expect(customRoleStore.getRole(role.id).enabled).toBe(false);
  });

  test('CR-23  deleteRole removes the role; getRole returns null afterward', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Temp Role', permissions: SOME_PERMS });
    customRoleStore.deleteRole(role.id, { deletedBy: 'admin1' });
    expect(customRoleStore.getRole(role.id)).toBeNull();
  });

  test('CR-24  deleteRole on an unknown ID throws NOT_FOUND', () => {
    const { customRoleStore } = freshCustomRoleStore();
    expect(() => customRoleStore.deleteRole('custom:nope'))
      .toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
  });

  test('CR-25  listRoles returns every created role, sorted by createdAt ascending', async () => {
    const { customRoleStore } = freshCustomRoleStore();
    const a = customRoleStore.createRole({ name: 'Role A', permissions: SOME_PERMS });
    await new Promise(r => setTimeout(r, 5));
    const b = customRoleStore.createRole({ name: 'Role B', permissions: SOME_PERMS });
    const listed = customRoleStore.listRoles();
    expect(listed.map(r => r.id)).toEqual([a.id, b.id]);
  });
});

describe('CR-26…CR-32  Authorization composition (authorize.js)', () => {
  test('CR-26  a custom role grants exactly its configured permissions', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const authorize = require('./authorize');
    const role = customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS });
    expect(authorize.isPermitted(role.id, 'READ_POLICIES')).toBe(true);
    expect(authorize.isPermitted(role.id, 'REVIEW_POLICY_CHANGE')).toBe(true);
    expect(authorize.isPermitted(role.id, 'MANAGE_USERS')).toBe(false);
  });

  test('CR-27  a disabled custom role is permitted nothing (fail-closed)', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const authorize = require('./authorize');
    const role = customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS });
    customRoleStore.updateRole(role.id, { enabled: false });
    expect(authorize.isPermitted(role.id, 'READ_POLICIES')).toBe(false);
  });

  test('CR-28  an unknown role (canonical or custom) is permitted nothing', () => {
    freshCustomRoleStore();
    const authorize = require('./authorize');
    expect(authorize.isPermitted('custom:does-not-exist', 'READ_POLICIES')).toBe(false);
    expect(authorize.isPermitted('not-a-role-at-all', 'READ_POLICIES')).toBe(false);
    expect(authorize.isPermitted(null, 'READ_POLICIES')).toBe(false);
    expect(authorize.isPermitted('admin', null)).toBe(false);
  });

  test('CR-29  canonical roles are evaluated identically through authorize.js and roles.js directly', () => {
    freshCustomRoleStore();
    const authorize = require('./authorize');
    for (const role of Object.values(ROLES)) {
      for (const perm of PERMISSION_SET) {
        expect(authorize.isPermitted(role, perm)).toBe(canonicalIsPermitted(role, perm));
      }
    }
  });

  test('CR-30  permissionsForRole returns a custom role\'s permission set', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const authorize = require('./authorize');
    const role = customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS });
    expect(authorize.permissionsForRole(role.id).sort()).toEqual([...SOME_PERMS].sort());
  });

  test('CR-31  isValidRoleOrCustom is true for canonical roles and existing custom roles, false otherwise', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const authorize = require('./authorize');
    const role = customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS });
    expect(authorize.isValidRoleOrCustom(ROLES.ADMIN)).toBe(true);
    expect(authorize.isValidRoleOrCustom(role.id)).toBe(true);
    expect(authorize.isValidRoleOrCustom('custom:nope')).toBe(false);
    expect(authorize.isValidRoleOrCustom('garbage')).toBe(false);
  });

  test('CR-32  a custom role can be granted an admin-exclusive permission — creation itself is the gate, not the matrix', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const authorize = require('./authorize');
    const role = customRoleStore.createRole({ name: 'Key Manager Lite', permissions: ['MANAGE_KEYS'] });
    expect(authorize.isPermitted(role.id, 'MANAGE_KEYS')).toBe(true);
  });
});

describe('CR-33…CR-38 Persistence / serialization', () => {
  test('CR-33 creating a role writes NO file — the running store never persists to JSON', () => {
    const { customRoleStore, tmpPath } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Persisted Role', permissions: SOME_PERMS });
    expect(fs.existsSync(tmpPath)).toBe(false);
    expect(customRoleStore.getRole(role.id)).toEqual(role);
  });

  test('CR-34  an explicit seed fixture round-trips: valid JSON with the expected shape, read back on reload', () => {
    const { customRoleStore, tmpPath } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Persisted Role', permissions: SOME_PERMS });
    customRoleStore.exportSeedFixture();
    const raw = JSON.parse(fs.readFileSync(tmpPath, 'utf8'));
    expect(raw.version).toBe(1);
    expect(raw.roles['custom:persisted-role']).toBeDefined();
    expect(raw.roles['custom:persisted-role'].permissions).toEqual(SOME_PERMS);
    customRoleStore._reload();
    expect(customRoleStore.getRole(role.id)).toEqual(role);
  });

  test('CR-35  loading from a missing store file starts empty, not an error', () => {
    const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-custom-role-missing-'));
    process.env.QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH = path.join(tmpDir, 'does-not-exist.json');
    jest.resetModules();
    const customRoleStore = require('./customRoleStore');
    customRoleStore._reset();
    expect(customRoleStore.listRoles()).toEqual([]);
  });

  test('CR-36  loading from a corrupt store file falls back to empty rather than throwing', () => {
    const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-custom-role-corrupt-'));
    const tmpPath = path.join(tmpDir, 'corrupt.json');
    fs.writeFileSync(tmpPath, '{ not valid json', 'utf8');
    process.env.QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH = tmpPath;
    jest.resetModules();
    const customRoleStore = require('./customRoleStore');
    customRoleStore._reset();
    expect(() => customRoleStore.listRoles()).not.toThrow();
    expect(customRoleStore.listRoles()).toEqual([]);
  });

  test('CR-37  an update is visible immediately and never rewrites the seed file', () => {
    const { customRoleStore, tmpPath } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Persisted Role', permissions: SOME_PERMS });
    customRoleStore.exportSeedFixture();
    const before = fs.readFileSync(tmpPath, 'utf8');
    customRoleStore.updateRole(role.id, { permissions: ['MANAGE_WEBHOOKS'] });
    expect(customRoleStore.getRole(role.id).permissions).toEqual(['MANAGE_WEBHOOKS']);
    expect(fs.readFileSync(tmpPath, 'utf8')).toBe(before);
  });

  test('CR-38  a deletion is visible immediately and never rewrites the seed file', () => {
    const { customRoleStore, tmpPath } = freshCustomRoleStore();
    const role = customRoleStore.createRole({ name: 'Persisted Role', permissions: SOME_PERMS });
    customRoleStore.exportSeedFixture();
    const before = fs.readFileSync(tmpPath, 'utf8');
    customRoleStore.deleteRole(role.id);
    expect(customRoleStore.getRole(role.id)).toBeNull();
    expect(fs.readFileSync(tmpPath, 'utf8')).toBe(before);
  });
});

describe('CR-39…CR-44  Backward compatibility with built-in roles', () => {
  test('CR-39  roles.js\'s canonical isPermitted/permissionsForRole/isValidRole are completely untouched by custom roles existing', () => {
    const { customRoleStore } = freshCustomRoleStore();
    const rolesBefore = require('./roles');
    const beforeAdminPerms = rolesBefore.permissionsForRole(ROLES.ADMIN);

    customRoleStore.createRole({ name: 'Anything', permissions: SOME_PERMS });

    const rolesAfter = require('./roles');
    expect(rolesAfter.permissionsForRole(ROLES.ADMIN)).toEqual(beforeAdminPerms);
    for (const role of Object.values(ROLES)) {
      for (const perm of PERMISSION_SET) {
        expect(rolesAfter.isPermitted(role, perm)).toBe(canonicalIsPermitted(role, perm));
      }
    }
  });

  test('CR-40  a user store assignment of a canonical role is unaffected by the custom role store existing', () => {
    const { store } = freshLinkedStores();
    const user = store.createUser({ username: 'alice', role: ROLES.OPERATOR, createdBy: 'system' });
    expect(user.role).toBe(ROLES.OPERATOR);
  });

  test('CR-41  a user can be assigned an existing custom role ID', () => {
    const { store, customRoleStore } = freshLinkedStores();
    const role = customRoleStore.createRole({ name: 'Policy Reviewer', permissions: SOME_PERMS });
    const user = store.createUser({ username: 'bob', role: role.id, createdBy: 'system' });
    expect(user.role).toBe(role.id);
  });

  test('CR-42  assigning a nonexistent custom role ID to a user is rejected the same way an invalid canonical role is', () => {
    const { store } = freshLinkedStores();
    expect(() => store.createUser({ username: 'carol', role: 'custom:does-not-exist' }))
      .toThrow(expect.objectContaining({ code: 'INVALID_ROLE' }));
    expect(() => store.createUser({ username: 'carol', role: 'not-a-role' }))
      .toThrow(expect.objectContaining({ code: 'INVALID_ROLE' }));
  });

  test('CR-43  the five built-in roles still validate as valid user roles with no custom role store entries at all', () => {
    const { store } = freshLinkedStores();
    for (const role of Object.values(ROLES)) {
      const user = store.createUser({ username: `user-${role}`, role, createdBy: 'system' });
      expect(user.role).toBe(role);
    }
  });

  test('CR-44  PERMISSIONS/ROLE_SET/ROLE_META in roles.js remain frozen and unchanged in shape', () => {
    freshCustomRoleStore();
    const { PERMISSIONS, ROLE_SET, ROLE_META } = require('./roles');
    expect(Object.isFrozen(PERMISSIONS)).toBe(true);
    expect(Object.isFrozen(ROLE_SET)).toBe(true);
    expect(Object.isFrozen(ROLE_META)).toBe(true);
    // 5 -> 6. Added ROLES.TENANT, the tenant self-service
    // portal's one role — deliberately NOT part of the 5-role console-
    // operator ladder this test otherwise pins (see roles.js's ROLES.TENANT
    // comment). Shape/frozen-ness invariants above are unchanged.
    expect(ROLE_SET.size).toBe(6);
  });
});
