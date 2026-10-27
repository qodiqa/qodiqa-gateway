'use strict';

// Unit tests for tenantKeyManager.js.
// keyStore is mocked — all tests run without a real key file.

jest.mock('../keyStore');
jest.mock('../../logger', () => ({ emit: jest.fn() }));

const keyStore         = require('../keyStore');
const { emit }         = require('../../logger');
const tenantKeyManager = require('../tenantKeyManager');

const NOW      = new Date('2024-06-01T00:00:00.000Z').getTime();
const DAY_MS   = 86_400_000;

const ROTATION_DAYS       = 90;
const EXPIRY_DAYS         = 180;
const EXPIRY_WARNING_DAYS = 30;

// Build a fake key record as returned by getKeysByClient().
function makeKey(overrides = {}) {
  const base = {
    clientId:     'test-client',
    keyId:        'test-client:key_v1',
    version:      1,
    algorithm:    'ed25519',
    publicKeyB64: 'base64pubkey==',
    status:       'active',
    createdAt:    new Date(NOW - 30 * DAY_MS).toISOString(), // 30 days ago
  };
  return { ...base, ...overrides };
}

beforeAll(() => {
  jest.useFakeTimers();
  jest.setSystemTime(NOW);
  // Set exported constants on the auto-mock (these are not functions, so
  // jest does not auto-mock them — we set them manually).
  keyStore.ROTATION_DAYS       = ROTATION_DAYS;
  keyStore.EXPIRY_DAYS         = EXPIRY_DAYS;
  keyStore.EXPIRY_WARNING_DAYS = EXPIRY_WARNING_DAYS;
});

afterAll(() => {
  jest.useRealTimers();
});

beforeEach(() => {
  jest.clearAllMocks();
  // Re-apply constants after clearAllMocks (clearAllMocks does not reset
  // non-function properties, but be explicit for safety).
  keyStore.ROTATION_DAYS       = ROTATION_DAYS;
  keyStore.EXPIRY_DAYS         = EXPIRY_DAYS;
  keyStore.EXPIRY_WARNING_DAYS = EXPIRY_WARNING_DAYS;
});

// ── getTenantKeyStatus ────────────────────────────────────────────────────────

describe('getTenantKeyStatus', () => {
  it('returns HEALTHY for a non-expired, non-overdue active key', () => {
    keyStore.getKeysByClient.mockReturnValue([makeKey()]);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.status).toBe('HEALTHY');
    expect(status.issues).toEqual([]);
    expect(status.activeKey).not.toBeNull();
    expect(status.activeKey.keyId).toBe('test-client:key_v1');
  });

  it('returns CRITICAL with NO_ACTIVE_KEY when store is empty', () => {
    keyStore.getKeysByClient.mockReturnValue([]);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.status).toBe('CRITICAL');
    expect(status.issues).toContain('NO_ACTIVE_KEY');
    expect(status.activeKey).toBeNull();
  });

  it('returns CRITICAL with KEY_EXPIRED when active key is expired', () => {
    // Created 200 days ago → expiresAt = 20 days ago (past)
    const key = makeKey({ createdAt: new Date(NOW - 200 * DAY_MS).toISOString() });
    keyStore.getKeysByClient.mockReturnValue([key]);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.status).toBe('CRITICAL');
    expect(status.issues).toContain('KEY_EXPIRED');
  });

  it('returns WARNING with KEY_EXPIRING when key expires within warning window', () => {
    // Created 160 days ago → 20 days until expiry (< 30 warning days)
    const key = makeKey({ createdAt: new Date(NOW - 160 * DAY_MS).toISOString() });
    keyStore.getKeysByClient.mockReturnValue([key]);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.status).toBe('WARNING');
    expect(status.issues).toContain('KEY_EXPIRING');
  });

  it('returns WARNING with KEY_ROTATION_OVERDUE when past rotation deadline', () => {
    // Created 100 days ago → rotation was due 10 days ago
    const key = makeKey({ createdAt: new Date(NOW - 100 * DAY_MS).toISOString() });
    keyStore.getKeysByClient.mockReturnValue([key]);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.status).toBe('WARNING');
    expect(status.issues).toContain('KEY_ROTATION_OVERDUE');
  });

  it('returns WARNING with MULTIPLE_ACTIVE_KEYS when two active keys exist', () => {
    const keys = [
      makeKey({ keyId: 'test-client:key_v1', version: 1 }),
      makeKey({ keyId: 'test-client:key_v2', version: 2, createdAt: new Date(NOW - 10 * DAY_MS).toISOString() }),
    ];
    keyStore.getKeysByClient.mockReturnValue(keys);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.status).toBe('WARNING');
    expect(status.issues).toContain('MULTIPLE_ACTIVE_KEYS');
  });

  it('selects the most recently created key when multiple active keys exist', () => {
    const older  = makeKey({ keyId: 'test-client:key_v1', version: 1, createdAt: new Date(NOW - 40 * DAY_MS).toISOString() });
    const newer  = makeKey({ keyId: 'test-client:key_v2', version: 2, createdAt: new Date(NOW - 10 * DAY_MS).toISOString() });
    keyStore.getKeysByClient.mockReturnValue([older, newer]);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.activeKey.keyId).toBe('test-client:key_v2');
  });

  it('deprecated keys do not count as active', () => {
    const keys = [
      makeKey({ keyId: 'test-client:key_v1', status: 'deprecated' }),
      makeKey({ keyId: 'test-client:key_v2', version: 2, status: 'active' }),
    ];
    keyStore.getKeysByClient.mockReturnValue(keys);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.activeKeyCount).toBe(1);
    expect(status.keyCount).toBe(2);
  });

  it('throws TypeError for invalid clientId', () => {
    expect(() => tenantKeyManager.getTenantKeyStatus('')).toThrow(TypeError);
    expect(() => tenantKeyManager.getTenantKeyStatus(null)).toThrow(TypeError);
    expect(() => tenantKeyManager.getTenantKeyStatus('bad client!')).toThrow(TypeError);
  });

  it('includes lifecycle fields on the activeKey', () => {
    keyStore.getKeysByClient.mockReturnValue([makeKey()]);
    const status = tenantKeyManager.getTenantKeyStatus('test-client');
    expect(status.activeKey).toHaveProperty('expiresAt');
    expect(status.activeKey).toHaveProperty('rotationDeadline');
    expect(status.activeKey).toHaveProperty('daysUntilExpiry');
    expect(status.activeKey).toHaveProperty('daysUntilRotation');
  });
});

// ── getKeyHealthSummary ───────────────────────────────────────────────────────

describe('getKeyHealthSummary', () => {
  it('returns HEALTHY overall when all tenants are healthy', () => {
    keyStore.listKeys.mockReturnValue([
      makeKey({ clientId: 'client-a', keyId: 'client-a:key_v1' }),
      makeKey({ clientId: 'client-b', keyId: 'client-b:key_v1' }),
    ]);
    keyStore.getKeysByClient.mockImplementation(clientId =>
      [makeKey({ clientId, keyId: `${clientId}:key_v1` })],
    );
    const summary = tenantKeyManager.getKeyHealthSummary();
    expect(summary.overallStatus).toBe('HEALTHY');
    expect(summary.totalTenants).toBe(2);
    expect(summary.healthyTenants).toBe(2);
    expect(summary.criticalTenants).toBe(0);
  });

  it('returns CRITICAL overall when any tenant is critical', () => {
    keyStore.listKeys.mockReturnValue([
      makeKey({ clientId: 'client-a', keyId: 'client-a:key_v1' }),
      // client-b has no key record in listKeys — no keys means empty getKeysByClient
    ]);
    keyStore.getKeysByClient.mockImplementation(clientId => {
      if (clientId === 'client-a') return [makeKey({ clientId: 'client-a', keyId: 'client-a:key_v1' })];
      return [];
    });
    // Force client-b into the list via the all-keys scan.
    // Actually, listKeys only returns 'client-a', so only one tenant is scanned.
    const summary = tenantKeyManager.getKeyHealthSummary();
    expect(summary.totalTenants).toBe(1);
    expect(summary.overallStatus).toBe('HEALTHY');
  });

  it('counts critical/warning/healthy correctly', () => {
    // client-a: healthy (30 days old)
    // client-b: warning (100 days old → rotation overdue)
    // client-c: critical (200 days old → expired)
    keyStore.listKeys.mockReturnValue([
      makeKey({ clientId: 'client-a', keyId: 'client-a:key_v1', createdAt: new Date(NOW - 30 * DAY_MS).toISOString() }),
      makeKey({ clientId: 'client-b', keyId: 'client-b:key_v1', createdAt: new Date(NOW - 100 * DAY_MS).toISOString() }),
      makeKey({ clientId: 'client-c', keyId: 'client-c:key_v1', createdAt: new Date(NOW - 200 * DAY_MS).toISOString() }),
    ]);
    keyStore.getKeysByClient.mockImplementation(clientId => {
      const daysAgo = { 'client-a': 30, 'client-b': 100, 'client-c': 200 }[clientId];
      return [makeKey({ clientId, keyId: `${clientId}:key_v1`, createdAt: new Date(NOW - daysAgo * DAY_MS).toISOString() })];
    });
    const summary = tenantKeyManager.getKeyHealthSummary();
    expect(summary.healthyTenants).toBe(1);
    expect(summary.warningTenants).toBe(1);
    expect(summary.criticalTenants).toBe(1);
    expect(summary.overallStatus).toBe('CRITICAL');
  });

  it('returns timestamp in ISO format', () => {
    keyStore.listKeys.mockReturnValue([]);
    const summary = tenantKeyManager.getKeyHealthSummary();
    expect(summary.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('returns empty tenants array when store is empty', () => {
    keyStore.listKeys.mockReturnValue([]);
    const summary = tenantKeyManager.getKeyHealthSummary();
    expect(summary.totalTenants).toBe(0);
    expect(summary.tenants).toEqual([]);
    expect(summary.overallStatus).toBe('HEALTHY');
  });
});

// ── ensureActiveKey ───────────────────────────────────────────────────────────

describe('ensureActiveKey', () => {
  it('returns no-op result for a healthy tenant', () => {
    keyStore.getKeysByClient.mockReturnValue([makeKey()]);
    const result = tenantKeyManager.ensureActiveKey('test-client');
    expect(result.provisioned).toBe(false);
    expect(result.rotated).toBe(false);
    expect(result.keyId).toBe('test-client:key_v1');
    expect(keyStore.rotateKeyGracefully).not.toHaveBeenCalled();
  });

  it('provisions a new key when no active key exists', () => {
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'test-client:key_v1', version: 1, clientId: 'test-client' });
    const result = tenantKeyManager.ensureActiveKey('test-client');
    expect(result.provisioned).toBe(true);
    expect(result.keyId).toBe('test-client:key_v1');
    expect(keyStore.rotateKeyGracefully).toHaveBeenCalledWith('test-client');
  });

  it('emits WARN TENANT_KEY_MISSING before provisioning', () => {
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'test-client:key_v1', version: 1, clientId: 'test-client' });
    tenantKeyManager.ensureActiveKey('test-client');
    expect(emit).toHaveBeenCalledWith('WARN', 'TENANT_KEY_MISSING', expect.objectContaining({ clientId: 'test-client' }));
  });

  it('emits INFO KEY_PROVISIONED after successful provisioning', () => {
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'test-client:key_v1', version: 1, clientId: 'test-client' });
    tenantKeyManager.ensureActiveKey('test-client');
    expect(emit).toHaveBeenCalledWith('INFO', 'KEY_PROVISIONED', expect.objectContaining({ clientId: 'test-client', keyId: 'test-client:key_v1' }));
  });

  it('auto-rotates an expired active key', () => {
    const expiredKey = makeKey({ createdAt: new Date(NOW - 200 * DAY_MS).toISOString() });
    keyStore.getKeysByClient.mockReturnValue([expiredKey]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'test-client:key_v2', version: 2, clientId: 'test-client' });
    const result = tenantKeyManager.ensureActiveKey('test-client');
    expect(result.rotated).toBe(true);
    expect(result.keyId).toBe('test-client:key_v2');
  });

  it('emits CRITICAL TENANT_KEY_EXPIRED_ACTIVE before auto-rotating', () => {
    const expiredKey = makeKey({ createdAt: new Date(NOW - 200 * DAY_MS).toISOString() });
    keyStore.getKeysByClient.mockReturnValue([expiredKey]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'test-client:key_v2', version: 2, clientId: 'test-client' });
    tenantKeyManager.ensureActiveKey('test-client');
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TENANT_KEY_EXPIRED_ACTIVE', expect.objectContaining({ clientId: 'test-client' }));
  });

  it('emits CRITICAL and throws when provisioning fails', () => {
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockImplementation(() => { throw new Error('disk full'); });
    expect(() => tenantKeyManager.ensureActiveKey('test-client')).toThrow('disk full');
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TENANT_KEY_PROVISIONING_FAILED', expect.objectContaining({ clientId: 'test-client' }));
  });

  it('emits CRITICAL and throws when auto-rotation of expired key fails', () => {
    const expiredKey = makeKey({ createdAt: new Date(NOW - 200 * DAY_MS).toISOString() });
    keyStore.getKeysByClient.mockReturnValue([expiredKey]);
    keyStore.rotateKeyGracefully.mockImplementation(() => { throw new Error('store locked'); });
    expect(() => tenantKeyManager.ensureActiveKey('test-client')).toThrow('store locked');
    expect(emit).toHaveBeenCalledWith('CRITICAL', 'TENANT_KEY_ROTATION_FAILED', expect.objectContaining({ clientId: 'test-client' }));
  });

  it('emits WARN for multiple active keys but does not rotate', () => {
    const keys = [
      makeKey({ keyId: 'test-client:key_v1', version: 1 }),
      makeKey({ keyId: 'test-client:key_v2', version: 2 }),
    ];
    keyStore.getKeysByClient.mockReturnValue(keys);
    tenantKeyManager.ensureActiveKey('test-client');
    expect(emit).toHaveBeenCalledWith('WARN', 'MULTIPLE_ACTIVE_KEYS_DETECTED', expect.objectContaining({ clientId: 'test-client' }));
    expect(keyStore.rotateKeyGracefully).not.toHaveBeenCalled();
  });

  it('throws TypeError for invalid clientId', () => {
    expect(() => tenantKeyManager.ensureActiveKey(null)).toThrow(TypeError);
  });
});

// ── ensureAllTenantsHaveActiveKeys ────────────────────────────────────────────

describe('ensureAllTenantsHaveActiveKeys', () => {
  it('returns provisioned result for tenant with no keys', () => {
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'c1:key_v1', version: 1, clientId: 'c1' });
    const { results } = tenantKeyManager.ensureAllTenantsHaveActiveKeys(['c1']);
    expect(results).toHaveLength(1);
    expect(results[0].provisioned).toBe(true);
    expect(results[0].error).toBeNull();
  });

  it('captures per-client failures without throwing', () => {
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockImplementation(() => { throw new Error('oops'); });
    const { results } = tenantKeyManager.ensureAllTenantsHaveActiveKeys(['c1']);
    expect(results[0].error).toBe('oops');
    expect(results[0].provisioned).toBe(false);
  });

  it('handles multiple clients independently', () => {
    keyStore.getKeysByClient
      .mockReturnValueOnce([makeKey({ clientId: 'c1', keyId: 'c1:key_v1' })])
      .mockReturnValueOnce([]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'c2:key_v1', version: 1, clientId: 'c2' });
    const { results } = tenantKeyManager.ensureAllTenantsHaveActiveKeys(['c1', 'c2']);
    expect(results).toHaveLength(2);
    expect(results[0].provisioned).toBe(false);
    expect(results[1].provisioned).toBe(true);
  });

  it('returns empty results for empty input', () => {
    const { results } = tenantKeyManager.ensureAllTenantsHaveActiveKeys([]);
    expect(results).toEqual([]);
  });
});

// ── validateAllTenantsAtStartup ───────────────────────────────────────────────

describe('validateAllTenantsAtStartup', () => {
  it('succeeds and returns health summary when all tenants are healthy', () => {
    keyStore.listKeys.mockReturnValue([
      makeKey({ clientId: 'main-client', keyId: 'main-client:key_v1' }),
    ]);
    keyStore.getKeysByClient.mockReturnValue([
      makeKey({ clientId: 'main-client', keyId: 'main-client:key_v1' }),
    ]);
    const summary = tenantKeyManager.validateAllTenantsAtStartup(['main-client']);
    expect(summary).toHaveProperty('overallStatus');
    expect(summary.overallStatus).toBe('HEALTHY');
  });

  it('provisions a missing key at startup and reports in summary', () => {
    keyStore.listKeys.mockReturnValue([]);
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockReturnValue({ keyId: 'new-client:key_v1', version: 1, clientId: 'new-client' });

    // After provisioning, getKeysByClient should return the new key.
    keyStore.getKeysByClient.mockReturnValueOnce([]).mockReturnValue([
      makeKey({ clientId: 'new-client', keyId: 'new-client:key_v1' }),
    ]);
    keyStore.listKeys.mockReturnValueOnce([]).mockReturnValue([
      makeKey({ clientId: 'new-client', keyId: 'new-client:key_v1' }),
    ]);

    const summary = tenantKeyManager.validateAllTenantsAtStartup(['new-client']);
    expect(keyStore.rotateKeyGracefully).toHaveBeenCalledWith('new-client');
    expect(emit).toHaveBeenCalledWith('INFO', 'TENANT_KEY_STARTUP_COMPLETE', expect.any(Object));
    expect(summary).toBeDefined();
  });

  it('emits TENANT_KEY_STARTUP_COMPLETE with correct counts', () => {
    keyStore.listKeys.mockReturnValue([
      makeKey({ clientId: 'main-client', keyId: 'main-client:key_v1' }),
    ]);
    keyStore.getKeysByClient.mockReturnValue([
      makeKey({ clientId: 'main-client', keyId: 'main-client:key_v1' }),
    ]);
    tenantKeyManager.validateAllTenantsAtStartup(['main-client']);
    expect(emit).toHaveBeenCalledWith('INFO', 'TENANT_KEY_STARTUP_COMPLETE', expect.objectContaining({
      totalTenants: 1,
      provisioned:  0,
      failed:       0,
    }));
  });

  it('throws if any provisioning attempt fails', () => {
    keyStore.listKeys.mockReturnValue([]);
    keyStore.getKeysByClient.mockReturnValue([]);
    keyStore.rotateKeyGracefully.mockImplementation(() => { throw new Error('no KEK'); });
    expect(() => tenantKeyManager.validateAllTenantsAtStartup(['failing-client'])).toThrow(
      /TenantKeyManager.*failing-client/,
    );
  });

  it('emits WARN for expiring key during startup', () => {
    const expiringKey = makeKey({ createdAt: new Date(NOW - 160 * DAY_MS).toISOString() });
    keyStore.listKeys.mockReturnValue([{ ...expiringKey }]);
    keyStore.getKeysByClient.mockReturnValue([expiringKey]);
    tenantKeyManager.validateAllTenantsAtStartup(['test-client']);
    expect(emit).toHaveBeenCalledWith('WARN', 'KEY_EXPIRING_SOON', expect.objectContaining({ clientId: 'test-client' }));
  });

  it('emits WARN for rotation-overdue key during startup', () => {
    const overdueKey = makeKey({ createdAt: new Date(NOW - 100 * DAY_MS).toISOString() });
    keyStore.listKeys.mockReturnValue([{ ...overdueKey }]);
    keyStore.getKeysByClient.mockReturnValue([overdueKey]);
    tenantKeyManager.validateAllTenantsAtStartup(['test-client']);
    expect(emit).toHaveBeenCalledWith('WARN', 'KEY_ROTATION_OVERDUE', expect.objectContaining({ clientId: 'test-client' }));
  });

  it('filters out invalid clientId strings from the input list', () => {
    keyStore.listKeys.mockReturnValue([]);
    keyStore.getKeysByClient.mockReturnValue([]);
    // These should be silently ignored.
    expect(() => tenantKeyManager.validateAllTenantsAtStartup([null, '', 'bad client!'])).not.toThrow();
  });

  it('works with no explicitly supplied client IDs (store-only)', () => {
    keyStore.listKeys.mockReturnValue([
      makeKey({ clientId: 'store-client', keyId: 'store-client:key_v1' }),
    ]);
    keyStore.getKeysByClient.mockReturnValue([
      makeKey({ clientId: 'store-client', keyId: 'store-client:key_v1' }),
    ]);
    const summary = tenantKeyManager.validateAllTenantsAtStartup([]);
    expect(summary.totalTenants).toBe(1);
  });
});
