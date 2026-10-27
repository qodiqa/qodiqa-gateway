'use strict';

/**
 * adapter-level tests for the three cloud KEK providers (aws-kms, azure-kv, gcp-kms), which had real SDK
 * call sites and no test at all. Each SDK is replaced by a STATEFUL fake that really wraps/unwraps (AES-256-GCM under
 * a fake master key), so the tests prove the adapter's own contract end to end:
 *
 *   CK-01 required configuration is refused before any SDK call
 *   CK-02 first run: a fresh 32-byte KEK is produced, only the WRAPPED form is persisted (never the plaintext)
 *   CK-03 second run: the persisted wrapped key is unwrapped back to the SAME KEK (restart continuity)
 *   CK-04 a wrong-length unwrap result fails closed
 *   CK-05 rotation persists a new wrapped key by tmp+rename, and the next boot recovers the rotated KEK
 *   CK-06 health check reports unhealthy (never throws) when the service errors or the key is disabled
 *   CK-07 shutdown zeroizes the in-memory KEK
 *   CK-08 a missing SDK gives an explicit install error, not a crash
 *
 * These are adapter tests against fakes. They do NOT prove behaviour against the real cloud services; that needs
 * emulators or sandboxes (README "Key management" states the maturity per backend).
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpFile = (name) => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-cloudkms-')), name);

// A fake master key service: wrap = AES-256-GCM under a fixed master key; `badLength` makes unwrap return 16 bytes.
function fakeMaster() {
  const mk = crypto.randomBytes(32);
  const state = { badLength: false, fail: null, calls: [] };
  const wrap = (pt) => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', mk, iv);
    const ct = Buffer.concat([c.update(pt), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]);
  };
  const unwrap = (blob) => {
    const b = Buffer.from(blob);
    const d = crypto.createDecipheriv('aes-256-gcm', mk, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    const pt = Buffer.concat([d.update(b.subarray(28)), d.final()]);
    return state.badLength ? pt.subarray(0, 16) : pt;
  };
  return { state, wrap, unwrap };
}

function awsSdk(m) {
  class GenerateDataKeyCommand { constructor(i) { this.input = i; this.kind = 'gen'; } }
  class DecryptCommand { constructor(i) { this.input = i; this.kind = 'dec'; } }
  class DescribeKeyCommand { constructor(i) { this.input = i; this.kind = 'desc'; } }
  class KMSClient {
    constructor(cfg) { this.cfg = cfg; }
    async send(cmd) {
      m.state.calls.push(cmd.kind);
      if (m.state.fail) throw new Error(m.state.fail);
      if (cmd.kind === 'gen') { const pt = crypto.randomBytes(32); return { Plaintext: pt, CiphertextBlob: m.wrap(pt) }; }
      if (cmd.kind === 'dec') return { Plaintext: m.unwrap(cmd.input.CiphertextBlob) };
      return { KeyMetadata: { KeyState: m.state.keyState || 'Enabled' } };
    }
    destroy() { m.state.destroyed = true; }
  }
  return { KMSClient, GenerateDataKeyCommand, DecryptCommand, DescribeKeyCommand };
}

function azureSdks(m) {
  class KeyClient {
    async getKey(name) {
      if (m.state.fail) throw new Error(m.state.fail);
      return { id: `https://vault/keys/${name}/1`, keyType: 'oct-HSM', properties: { enabled: m.state.enabled !== false } };
    }
  }
  class CryptographyClient {
    async wrapKey(alg, k) { m.state.calls.push(`wrap:${alg}`); return { result: m.wrap(k) }; }
    async unwrapKey(alg, k) { m.state.calls.push(`unwrap:${alg}`); return { result: m.unwrap(k) }; }
  }
  class DefaultAzureCredential {}
  return { keys: { KeyClient, CryptographyClient }, identity: { DefaultAzureCredential } };
}

function gcpSdk(m) {
  class KeyManagementServiceClient {
    async encrypt({ name, plaintext }) { m.state.calls.push(`enc:${name}`); return [{ ciphertext: m.wrap(plaintext) }]; }
    async decrypt({ ciphertext }) { m.state.calls.push('dec'); return [{ plaintext: m.unwrap(ciphertext) }]; }
    async getCryptoKey() { if (m.state.fail) throw new Error(m.state.fail); return [{}]; }
    async close() { m.state.closed = true; }
  }
  return { KeyManagementServiceClient };
}

const CASES = [
  {
    label: 'aws-kms',
    load(m) {
      jest.resetModules();
      jest.doMock('@aws-sdk/client-kms', () => awsSdk(m), { virtual: true });
      return require('../awsKms').AwsKmsKekProvider;
    },
    loadMissing() {
      jest.resetModules();
      jest.doMock('@aws-sdk/client-kms', () => { throw new Error('Cannot find module'); }, { virtual: true });
      return require('../awsKms').AwsKmsKekProvider;
    },
    opts: (file) => ({ keyId: 'arn:aws:kms:eu-west-1:1:key/k', region: 'eu-west-1', edkPath: file }),
    missing: [[{ region: 'r' }, /AWS_KMS_KEY_ID/], [{ keyId: 'k' }, /AWS_KMS_REGION/]],
    disable(m) { m.state.keyState = 'Disabled'; },
  },
  {
    label: 'azure-kv',
    load(m) {
      jest.resetModules();
      const s = azureSdks(m);
      jest.doMock('@azure/keyvault-keys', () => s.keys, { virtual: true });
      jest.doMock('@azure/identity', () => s.identity, { virtual: true });
      return require('../azureKeyVault').AzureKeyVaultKekProvider;
    },
    loadMissing() {
      jest.resetModules();
      jest.doMock('@azure/keyvault-keys', () => { throw new Error('Cannot find module'); }, { virtual: true });
      jest.doMock('@azure/identity', () => ({}), { virtual: true });
      return require('../azureKeyVault').AzureKeyVaultKekProvider;
    },
    opts: (file) => ({ vaultUri: 'https://vault.example', keyName: 'kek', wrappedKeyPath: file }),
    missing: [[{ keyName: 'k' }, /AZURE_KEY_VAULT_URI/], [{ vaultUri: 'https://v' }, /AZURE_KEY_VAULT_KEY_NAME/]],
    disable(m) { m.state.enabled = false; },
  },
  {
    label: 'gcp-kms',
    load(m) {
      jest.resetModules();
      jest.doMock('@google-cloud/kms', () => gcpSdk(m), { virtual: true });
      return require('../gcpKms').GcpKmsKekProvider;
    },
    loadMissing() {
      jest.resetModules();
      jest.doMock('@google-cloud/kms', () => { throw new Error('Cannot find module'); }, { virtual: true });
      return require('../gcpKms').GcpKmsKekProvider;
    },
    opts: (file) => ({ project: 'p', keyring: 'r', key: 'k', wrappedKeyPath: file }),
    missing: [[{ keyring: 'r', key: 'k' }, /GCP_KMS_PROJECT/], [{ project: 'p', key: 'k' }, /GCP_KMS_KEYRING/], [{ project: 'p', keyring: 'r' }, /GCP_KMS_KEY\b/]],
    disable: null, // the GCP adapter's health check is reachability only
  },
];

const ENV_KEYS = ['AWS_KMS_KEY_ID', 'AWS_KMS_REGION', 'AWS_KMS_EDK_PATH', 'AZURE_KEY_VAULT_URI', 'AZURE_KEY_VAULT_KEY_NAME',
  'AZURE_KEY_VAULT_KEY_VER', 'AZURE_WRAPPED_KEY_PATH', 'GCP_KMS_PROJECT', 'GCP_KMS_KEYRING', 'GCP_KMS_KEY', 'GCP_WRAPPED_KEY_PATH'];
const saved = {};
beforeAll(() => { for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; } });
afterAll(() => { for (const k of ENV_KEYS) if (saved[k] !== undefined) process.env[k] = saved[k]; });
afterEach(() => jest.dontMock('@aws-sdk/client-kms'));

describe.each(CASES)('$label KEK provider', (c) => {
  test('CK-01 required configuration is refused before any SDK call', async () => {
    const m = fakeMaster();
    const P = c.load(m);
    for (const [opts, re] of c.missing) {
      await expect(new P({ ...opts, edkPath: tmpFile('x'), wrappedKeyPath: tmpFile('x') }).initialize()).rejects.toThrow(re);
    }
    expect(m.state.calls).toEqual([]);
  });

  test('CK-02/03 first run persists only the wrapped key; a restart unwraps the same KEK', async () => {
    const m = fakeMaster();
    const file = tmpFile('kek.wrapped');
    const P = c.load(m);
    const a = new P(c.opts(file));
    await a.initialize();
    const kek = Buffer.from(await a.getWrappingKey());
    expect(kek).toHaveLength(32);
    const persisted = fs.readFileSync(file, 'utf8').trim();
    expect(Buffer.from(persisted, 'base64').includes(kek)).toBe(false); // never the plaintext
    expect(persisted).not.toContain(kek.toString('base64'));
    expect(m.unwrap(Buffer.from(persisted, 'base64')).equals(kek)).toBe(true);

    const b = new (c.load(m))(c.opts(file));
    await b.initialize();
    expect(Buffer.from(await b.getWrappingKey()).equals(kek)).toBe(true);
  });

  test('CK-04 a wrong-length unwrap result fails closed', async () => {
    const m = fakeMaster();
    const file = tmpFile('kek.wrapped');
    await new (c.load(m))(c.opts(file)).initialize();
    m.state.badLength = true;
    await expect(new (c.load(m))(c.opts(file)).initialize()).rejects.toThrow(/expected 32/);
  });

  test('CK-05 rotation is tmp+rename and the next boot recovers the rotated KEK', async () => {
    const m = fakeMaster();
    const file = tmpFile('kek.wrapped');
    const p = new (c.load(m))(c.opts(file));
    await p.initialize();
    const before = Buffer.from(await p.getWrappingKey());
    const res = await p.rotateWrappingKey();
    expect(res.version).toMatch(/rotated/);
    const after = Buffer.from(await p.getWrappingKey());
    expect(after.equals(before)).toBe(false);
    expect(fs.existsSync(`${file}.tmp`)).toBe(false);
    const q = new (c.load(m))(c.opts(file));
    await q.initialize();
    expect(Buffer.from(await q.getWrappingKey()).equals(after)).toBe(true);
  });

  test('CK-06 health check reports unhealthy instead of throwing', async () => {
    const m = fakeMaster();
    const p = new (c.load(m))(c.opts(tmpFile('kek.wrapped')));
    await p.initialize();
    expect((await p.healthCheck()).healthy).toBe(true);
    if (c.disable) {
      c.disable(m);
      expect((await p.healthCheck()).healthy).toBe(false);
    }
    m.state.fail = 'service unreachable';
    m.state.keyState = undefined; m.state.enabled = undefined;
    const h = await p.healthCheck();
    expect(h.healthy).toBe(false);
    expect(h.detail).toMatch(/unreachable/i);
  });

  test('CK-07 shutdown zeroizes the KEK and refuses further use', async () => {
    const m = fakeMaster();
    const p = new (c.load(m))(c.opts(tmpFile('kek.wrapped')));
    await p.initialize();
    const ref = await p.getWrappingKey();
    await p.shutdown();
    expect(ref.every((b) => b === 0)).toBe(true);
    await expect(p.getWrappingKey()).rejects.toThrow(/not initialized/);
  });

  // phase 6: rotation writes the wrapped key through the shared secure writer (unique
  // 0600 temp, fsync, rename) — a stale or concurrent writer's fixed '<file>.tmp' can no longer break or race it.
  test('CK-12 rotation is unaffected by a stale <file>.tmp and fsyncs the new wrapped key before the rename', async () => {
    const m = fakeMaster();
    const file = tmpFile('kek.wrapped');
    const p = new (c.load(m))(c.opts(file));
    await p.initialize();
    fs.mkdirSync(`${file}.tmp`); // a leftover the old fixed-name writer could not write through (EISDIR)
    const fsync = jest.spyOn(fs, 'fsyncSync');
    try {
      await p.rotateWrappingKey();
      expect(fsync).toHaveBeenCalled();
    } finally { fsync.mockRestore(); }
    const after = Buffer.from(await p.getWrappingKey());
    const q = new (c.load(m))(c.opts(file));
    await q.initialize();
    expect(Buffer.from(await q.getWrappingKey()).equals(after)).toBe(true);
  });

  // production never mints a KEK implicitly when the wrapped-key file is missing.
  describe('explicit wrapped-KEK provisioning (production)', () => {
    const saved17 = {};
    beforeEach(() => { for (const k of ['NODE_ENV', 'QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY']) saved17[k] = process.env[k]; process.env.NODE_ENV = 'production'; delete process.env.QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY; });
    afterEach(() => { for (const [k, v] of Object.entries(saved17)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });
    const minted = (calls) => calls.filter((c) => c === 'gen' || /^wrap:/.test(c) || /^enc:/.test(c));

    test('CK-09 missing wrapped-key file, no switch → KMS_WRAPPED_KEY_MISSING before any KMS generate/wrap call; nothing written', async () => {
      const m = fakeMaster();
      const file = tmpFile('kek.wrapped');
      let err;
      try { await new (c.load(m))(c.opts(file)).initialize(); } catch (e) { err = e; }
      expect(err && err.code).toBe('KMS_WRAPPED_KEY_MISSING');
      expect(err.message).toMatch(/QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true/);
      expect(fs.existsSync(file)).toBe(false);
      expect(minted(m.state.calls)).toEqual([]);
    });

    test('CK-10 the explicit switch provisions a new KEK; a restart without the switch unwraps the same KEK', async () => {
      const m = fakeMaster();
      const file = tmpFile('kek.wrapped');
      process.env.QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY = 'true';
      const a = new (c.load(m))(c.opts(file));
      await a.initialize();
      const kek = Buffer.from(await a.getWrappingKey());
      expect(fs.existsSync(file)).toBe(true);
      delete process.env.QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY;
      const b = new (c.load(m))(c.opts(file));
      await b.initialize();
      expect(Buffer.from(await b.getWrappingKey()).equals(kek)).toBe(true);
    });

    test('CK-11 only the exact string "true" is the switch', async () => {
      for (const v of ['1', 'TRUE', 'yes']) {
        process.env.QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY = v;
        const m = fakeMaster();
        await expect(new (c.load(m))(c.opts(tmpFile('kek.wrapped'))).initialize()).rejects.toThrow(/KMS_WRAPPED_KEY_MISSING/);
      }
    });
  });

  test('CK-08 a missing SDK gives an explicit install error', async () => {
    const P = c.loadMissing();
    await expect(new P(c.opts(tmpFile('kek.wrapped'))).initialize()).rejects.toThrow(/not installed/);
  });
});
