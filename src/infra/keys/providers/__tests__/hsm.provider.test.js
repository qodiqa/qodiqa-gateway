'use strict';

/**
 * HsmSigningProvider (PKCS#11) — revocation unit tests
 *
 * src/infra/keys/providers/hsm.js is the PKCS#11 NativeSigningProvider
 * actually wired to production via keyProviderFactory → keyStore.revokeKeyAsync.
 * These tests exercise its revokeKey() directly against a mocked pkcs11js
 * binding, independent of the higher-level keyStore mock-provider tests in
 * services/artifact/keyRevocation.async.test.js.
 */

const PKCS11_CONSTANTS = {
  CKF_SERIAL_SESSION: 'CKF_SERIAL_SESSION',
  CKF_RW_SESSION:     'CKF_RW_SESSION',
  CKU_USER:           'CKU_USER',
  CKA_CLASS:          'CKA_CLASS',
  CKA_LABEL:          'CKA_LABEL',
  CKA_KEY_TYPE:       'CKA_KEY_TYPE',
  CKO_PRIVATE_KEY:    'CKO_PRIVATE_KEY',
  CKO_PUBLIC_KEY:     'CKO_PUBLIC_KEY',
};

function makeMockPkcs11({ handlesByClass = {}, destroyImpl = null } = {}) {
  const calls = { C_DestroyObject: [], C_FindObjectsInit: [] };

  class MockPKCS11 {
    load() {}
    C_Initialize() {}
    C_GetSlotList() { return [0]; }
    C_OpenSession() { return 'session-1'; }
    C_Login() {}
    C_Logout() {}
    C_CloseSession() {}
    C_Finalize() {}

    C_FindObjectsInit(session, template) {
      calls.C_FindObjectsInit.push(template);
      this._lastClass = template.find(t => t.type === PKCS11_CONSTANTS.CKA_CLASS)?.value;
    }
    C_FindObjects() {
      return handlesByClass[this._lastClass] || [];
    }
    C_FindObjectsFinal() {}
    C_DestroyObject(session, handle) {
      calls.C_DestroyObject.push(handle);
      if (destroyImpl) destroyImpl(handle);
    }
  }

  return { pkcs11Module: { PKCS11: MockPKCS11, ...PKCS11_CONSTANTS }, calls };
}

function loadProvider(mockPkcs11Module) {
  jest.resetModules();
  jest.doMock('pkcs11js', () => mockPkcs11Module, { virtual: true });
  const { HsmSigningProvider } = require('../hsm');
  return HsmSigningProvider;
}

async function makeInitializedProvider(mockPkcs11Module, keyIndexPath) {
  const HsmSigningProvider = loadProvider(mockPkcs11Module);
  const provider = new HsmSigningProvider({
    libPath: '/fake/lib.so',
    slotIndex: 0,
    pin: '1234',
    keyIndexPath,
  });
  await provider.initialize();
  return provider;
}

const fs   = require('fs');
const os   = require('os');
const path = require('path');

function tempKeyIndexPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-hsm-provider-test-'));
  return path.join(dir, 'hsm-keys.json');
}

afterEach(() => {
  jest.dontMock('pkcs11js');
});

describe('HsmSigningProvider.getRevocationCapabilities', () => {
  test('advertises only "destroy" — PKCS#11 has no durable disable primitive', async () => {
    const { pkcs11Module } = makeMockPkcs11();
    const provider = await makeInitializedProvider(pkcs11Module, tempKeyIndexPath());
    expect(provider.getRevocationCapabilities()).toEqual(['destroy']);
  });
});

describe('HsmSigningProvider.revokeKey — success', () => {
  test('destroys both private and public key objects and marks the key index revoked', async () => {
    const { pkcs11Module, calls } = makeMockPkcs11({
      handlesByClass: {
        CKO_PRIVATE_KEY: ['priv-handle'],
        CKO_PUBLIC_KEY:  ['pub-handle'],
      },
    });
    const keyIndexPath = tempKeyIndexPath();
    const provider = await makeInitializedProvider(pkcs11Module, keyIndexPath);
    provider._keyIndex['default:key_v1'] = { keyName: 'default:key_v1', status: 'active', createdAt: new Date().toISOString(), algorithm: 'ed25519' };

    const result = await provider.revokeKey('default:key_v1', {});

    expect(result).toEqual(expect.objectContaining({
      method: 'destroy',
      providerResponse: { destroyedObjectCount: 2 },
    }));
    expect(calls.C_DestroyObject).toEqual(['priv-handle', 'pub-handle']);
    expect(provider._keyIndex['default:key_v1'].status).toBe('revoked');

    // Persisted to disk, not just in memory.
    const onDisk = JSON.parse(fs.readFileSync(keyIndexPath, 'utf8'));
    expect(onDisk['default:key_v1'].status).toBe('revoked');
    // the revocation time is persisted in the index and equals the reported one
    expect(onDisk['default:key_v1'].revokedAt).toBe(result.revokedAt);
  });

  // phase 6: the index goes through the shared secure writer — a stale fixed
  // '<index>.tmp' (here a directory, which the old writer could not write through) no longer blocks persisting a revocation.
  test('persists the revoked index despite a stale <index>.tmp, fsyncing before the rename', async () => {
    const { pkcs11Module } = makeMockPkcs11({ handlesByClass: { CKO_PRIVATE_KEY: ['priv-handle'] } });
    const keyIndexPath = tempKeyIndexPath();
    const provider = await makeInitializedProvider(pkcs11Module, keyIndexPath);
    provider._keyIndex['default:key_v1'] = { keyName: 'default:key_v1', status: 'active', createdAt: new Date().toISOString(), algorithm: 'ed25519' };
    fs.mkdirSync(`${keyIndexPath}.tmp`, { recursive: true });
    const fsync = jest.spyOn(fs, 'fsyncSync');
    try {
      await provider.revokeKey('default:key_v1', {});
      expect(fsync).toHaveBeenCalled();
    } finally { fsync.mockRestore(); }
    expect(JSON.parse(fs.readFileSync(keyIndexPath, 'utf8'))['default:key_v1'].status).toBe('revoked');
  });

  test('defaults to the strongest supported method when opts.method is omitted', async () => {
    const { pkcs11Module } = makeMockPkcs11({
      handlesByClass: { CKO_PRIVATE_KEY: ['priv-handle'] },
    });
    const provider = await makeInitializedProvider(pkcs11Module, tempKeyIndexPath());
    const result = await provider.revokeKey('default:key_v1');
    expect(result.method).toBe('destroy');
  });
});

describe('HsmSigningProvider.revokeKey — failure modes', () => {
  test('rejects an unsupported revocation method rather than silently downgrading', async () => {
    const { pkcs11Module } = makeMockPkcs11();
    const provider = await makeInitializedProvider(pkcs11Module, tempKeyIndexPath());
    await expect(provider.revokeKey('default:key_v1', { method: 'disable' }))
      .rejects.toThrow(/unsupported revocation method "disable"/);
  });

  test('throws when zero key objects are found on the HSM — never resolves as a silent no-op', async () => {
    const { pkcs11Module } = makeMockPkcs11({ handlesByClass: {} });
    const provider = await makeInitializedProvider(pkcs11Module, tempKeyIndexPath());
    await expect(provider.revokeKey('default:key_v1', {}))
      .rejects.toThrow(/nothing was destroyed/);
  });

  test('wraps and rethrows a C_DestroyObject failure, attaching the underlying cause', async () => {
    const { pkcs11Module } = makeMockPkcs11({
      handlesByClass: { CKO_PRIVATE_KEY: ['priv-handle'] },
      destroyImpl: () => { throw new Error('CKR_DEVICE_ERROR'); },
    });
    const provider = await makeInitializedProvider(pkcs11Module, tempKeyIndexPath());

    await expect(provider.revokeKey('default:key_v1', {})).rejects.toThrow(/C_DestroyObject failed/);
    try {
      await provider.revokeKey('default:key_v1', {});
      throw new Error('expected revokeKey to reject');
    } catch (err) {
      expect(err.cause).toBeInstanceOf(Error);
      expect(err.cause.message).toBe('CKR_DEVICE_ERROR');
      expect(err.method).toBe('destroy');
    }
  });

  test('throws when not initialized', async () => {
    const { pkcs11Module } = makeMockPkcs11();
    const HsmSigningProvider = loadProvider(pkcs11Module);
    const provider = new HsmSigningProvider({ libPath: '/fake/lib.so', keyIndexPath: tempKeyIndexPath() });
    await expect(provider.revokeKey('default:key_v1', {})).rejects.toThrow(/not initialized/);
  });
});

// the PKCS#11 contract SoftHSM2 enforces, captured by scripts/dep11/run-softhsm.js. Before the
// fixes, key generation used the signing mechanism, read the key pair as an array, used an undefined key-type
// constant, built the SPKI with an import format Node does not have, and leaked an initialized library on failure.
describe('HsmSigningProvider — real PKCS#11 contract', () => {
  const crypto = require('crypto');
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const ecPoint = Buffer.concat([Buffer.from([0x04, 0x20]), spki.subarray(12)]);   // DER OCTET STRING, as SoftHSM returns

  function realisticPkcs11(overrides = {}) {
    const calls = { generate: [], finalize: 0 };
    class P {
      load() {}
      C_Initialize() {}
      C_GetSlotList() { return overrides.slots || [0]; }
      C_OpenSession() { return 's'; }
      C_Login() { if (overrides.loginError) throw overrides.loginError; }
      C_Logout() {}
      C_CloseSession() {}
      C_Finalize() { calls.finalize++; }
      C_GenerateKeyPair(session, mech, pub, priv) {
        calls.generate.push({ mech, pub, priv });
        return { publicKey: 'pub-h', privateKey: 'priv-h' };                       // pkcs11js 2.x: an object
      }
      C_GetAttributeValue() { return [{ value: ecPoint }]; }
    }
    return { mod: { PKCS11: P, ...PKCS11_CONSTANTS, CKA_TOKEN: 'CKA_TOKEN', CKA_VERIFY: 'CKA_VERIFY', CKA_SIGN: 'CKA_SIGN', CKA_SENSITIVE: 'CKA_SENSITIVE', CKA_EXTRACTABLE: 'CKA_EXTRACTABLE', CKA_EC_PARAMS: 'CKA_EC_PARAMS', CKA_EC_POINT: 'CKA_EC_POINT' }, calls };
  }

  test('DEP11-H1 generateKeyPair uses CKM_EC_EDWARDS_KEY_PAIR_GEN and CKK_EC_EDWARDS, reads the KeyPair object, returns the SPKI', async () => {
    const { mod, calls } = realisticPkcs11();
    const provider = await makeInitializedProvider(mod, tempKeyIndexPath());
    const { publicKeyDer } = await provider.generateKeyPair('k1');
    expect(calls.generate[0].mech).toEqual({ mechanism: 0x1055 });
    for (const tmpl of [calls.generate[0].pub, calls.generate[0].priv]) {
      expect(tmpl.find((a) => a.type === 'CKA_KEY_TYPE').value).toBe(0x40);
    }
    expect(Buffer.compare(publicKeyDer, spki)).toBe(0);
  });

  test('DEP11-H2 a CKA_EC_POINT that is not a 32-byte Ed25519 point is refused', async () => {
    const { mod } = realisticPkcs11();
    mod.PKCS11.prototype.C_GetAttributeValue = () => [{ value: Buffer.alloc(33) }];
    const provider = await makeInitializedProvider(mod, tempKeyIndexPath());
    await expect(provider.generateKeyPair('k1')).rejects.toThrow(/not a 32-byte Ed25519 point/);
  });

  test('DEP11-H3 a failed initialize() (wrong PIN, missing slot) finalizes the library and rethrows the real error', async () => {
    const pinErr = Object.assign(new Error('CKR_PIN_INCORRECT'), { code: 0xa0 });
    const a = realisticPkcs11({ loginError: pinErr });
    await expect(makeInitializedProvider(a.mod, tempKeyIndexPath())).rejects.toBe(pinErr);
    expect(a.calls.finalize).toBe(1);
    const b = realisticPkcs11({ slots: [] });
    await expect(makeInitializedProvider(b.mod, tempKeyIndexPath())).rejects.toThrow(/slot 0 not found/);
    expect(b.calls.finalize).toBe(1);
  });
});
