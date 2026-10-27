'use strict';

/**
 * Stage 29 (G-1): keyManager.getTransparencyKeyStatus (added in Stage 27) against the REAL transparency key store.
 *
 * Isolation: no store path is set here. test/support/jest.setup.js gives this test file its own mkdtemp directory under os.tmpdir()
 * (prefix qodiqa-test-ts-, QODIQA_TRANSPARENCY_KEYS_PATH set before any module is required), a test-only KEK, and one
 * provisioned active key; test/support/jest.tmpdirTracker.js records the directory and test/support/jest.globalTeardown.js removes it. The
 * transparency key store has no network, PostgreSQL, Redis or control-plane I/O. Keys are ephemeral test keys
 * generated in that directory; no key material is read, printed or persisted by this suite (only keyIds and statuses).
 *
 *   TKS-01  unknown keyId → null (also an artifact-format keyId: the artifact store is never consulted)
 *   TKS-02  the active key → 'active'
 *   TKS-03  after a graceful rotation the outgoing key → 'deprecated', the new key → 'active'
 *   TKS-04  a revoked key → 'revoked'
 *   TKS-05  keyManager.getTransparencyKeyStatus agrees with transparencyKeyStore.getKeyStatus for every key
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const keyManager = require('../../../../services/artifact/keyManager');
const tKeyStore  = require('../transparencyKeyStore');

const idsWith = (status) => tKeyStore.listKeys().filter((k) => k.status === status).map((k) => k.keyId);
const activeId = () => { const ids = idsWith('active'); expect(ids).toHaveLength(1); return ids[0]; };

describe('keyManager.getTransparencyKeyStatus — real transparency key store (Stage 29 G-1)', () => {
  test('TKS-01 an unknown keyId returns null; an artifact-format keyId returns null', () => {
    expect(keyManager.getTransparencyKeyStatus('tr-no-such-client:key_v999')).toBeNull();
    expect(keyManager.getTransparencyKeyStatus('default:key_v1')).toBeNull();
  });

  test('TKS-02 the active key returns "active"', () => {
    const id = activeId();
    expect(keyManager.getTransparencyKeyStatus(id)).toBe('active');
  });

  test('TKS-03 a graceful rotation leaves the outgoing key "deprecated" and the new key "active"', () => {
    const before = activeId();
    tKeyStore.rotateKeyGracefully();
    const after = activeId();
    expect(after).not.toBe(before);
    expect(keyManager.getTransparencyKeyStatus(before)).toBe('deprecated');
    expect(keyManager.getTransparencyKeyStatus(after)).toBe('active');
  });

  test('TKS-04 a revoked key returns "revoked"', () => {
    const deprecated = idsWith('deprecated');
    expect(deprecated.length).toBeGreaterThan(0);
    const target = deprecated[0];
    tKeyStore.revokeKey(target);
    expect(keyManager.getTransparencyKeyStatus(target)).toBe('revoked');
  });

  test('TKS-05 agrees with transparencyKeyStore.getKeyStatus for every key in the store', () => {
    const keys = tKeyStore.listKeys();
    expect(new Set(keys.map((k) => k.status))).toEqual(new Set(['active', 'revoked']));
    for (const k of keys) expect(keyManager.getTransparencyKeyStatus(k.keyId)).toBe(tKeyStore.getKeyStatus(k.keyId));
  });
});
