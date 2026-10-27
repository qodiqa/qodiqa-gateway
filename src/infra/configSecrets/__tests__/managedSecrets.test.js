'use strict';

const {
  MANAGED_CONFIG_SECRETS,
  MANAGED_CONFIG_SECRET_NAMES,
  isManagedConfigSecret,
  UNREACHABLE_FROM_NODE_PROCESS,
} = require('../managedSecrets');

describe('managedSecrets', () => {
  test('every entry has a non-empty string name and purpose', () => {
    for (const entry of MANAGED_CONFIG_SECRETS) {
      expect(typeof entry.name).toBe('string');
      expect(entry.name.length).toBeGreaterThan(0);
      expect(typeof entry.purpose).toBe('string');
      expect(entry.purpose.length).toBeGreaterThan(0);
      expect(typeof entry.required).toBe('boolean');
    }
  });

  test('names are unique', () => {
    const unique = new Set(MANAGED_CONFIG_SECRET_NAMES);
    expect(unique.size).toBe(MANAGED_CONFIG_SECRET_NAMES.length);
  });

  test('does not include KEK/execution-invariant secret or the non-secret client id', () => {
    expect(MANAGED_CONFIG_SECRET_NAMES).not.toContain('QODIQA_KEY_ENCRYPTION_KEY');
    expect(MANAGED_CONFIG_SECRET_NAMES).not.toContain('QODIQA_EXECUTION_INVARIANT_SECRET');
    expect(MANAGED_CONFIG_SECRET_NAMES).not.toContain('QODIQA_CLIENT_ID');
  });

  test('does not include the Vault bootstrap auth vars themselves', () => {
    for (const v of ['VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_ROLE_ID', 'VAULT_SECRET_ID', 'VAULT_NAMESPACE']) {
      expect(MANAGED_CONFIG_SECRET_NAMES).not.toContain(v);
    }
  });

  test('isManagedConfigSecret reflects the list', () => {
    expect(isManagedConfigSecret('REDIS_PASSWORD')).toBe(true);
    expect(isManagedConfigSecret('OPENAI_API_KEY')).toBe(true);
    expect(isManagedConfigSecret('NOT_A_REAL_VAR')).toBe(false);
    expect(isManagedConfigSecret('QODIQA_CLIENT_ID')).toBe(false);
  });

  test('UNREACHABLE_FROM_NODE_PROCESS names are documented as excluded and are not managed', () => {
    expect(UNREACHABLE_FROM_NODE_PROCESS.length).toBeGreaterThan(0);
    for (const name of UNREACHABLE_FROM_NODE_PROCESS) {
      expect(isManagedConfigSecret(name)).toBe(false);
    }
  });

  test('list and name array are frozen', () => {
    expect(Object.isFrozen(MANAGED_CONFIG_SECRETS)).toBe(true);
    expect(Object.isFrozen(MANAGED_CONFIG_SECRET_NAMES)).toBe(true);
  });
});
