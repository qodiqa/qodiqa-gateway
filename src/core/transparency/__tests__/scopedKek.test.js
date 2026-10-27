'use strict';

/**
 * dedicated key-encryption keys for the audit key stores (transparency, audit checkpoint).
 *
 *   SK-01  secretsProvider: a scope with no variable uses the shared KEK; a set variable replaces it for that scope only; malformed or trivial
 *          values and unknown scopes are hard failures (never a silent fallback)
 *   SK-02  the transparency and checkpoint key files are encrypted, MAC-sealed and fingerprinted under their OWN KEK: each opens only under it
 *   SK-03  starting a store under a different / removed / added scoped KEK fails closed with KEK_FINGERPRINT_MISMATCH naming the variable in use
 *   SK-04  an unset KEK (nothing configured at all) fails closed before any key is created
 *   SK-05  with no scoped variable nothing changes: the stores keep the shared KEK and their existing files stay readable
 *   SK-06  the boot validator: malformed values; QODIQA_AUDIT_KEK_SEPARATION off / warn / enforce in production
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

// three distinct, non-repeating 256-bit test values (a repeating pattern is refused as a trivial key)
const SHARED = '3f9a1c7e5b2d804f6a1e93c7d05b48e2a7f61c3950d8e4b27a96f13c5e80d4b1';
const TR = '8d27f0a4c91e53b6074ad2e8159c3f60b7e41a8d95c20f3e6ab7d148c05e92f7';
const CP = 'c41e7a09d3586bf2e0149a7c85d3f1b6290e8d47a3c5f61b8e02d9740a1f3c58';
const OTHER = '5e60b9d2147a8c3fe1d05a9467b2c8f31d4e7a60c9b358f2a0e1d7463c85b9fa';
const TR_ENV = 'QODIQA_TRANSPARENCY_KEY_ENCRYPTION_KEY';
const CP_ENV = 'QODIQA_CHECKPOINT_KEY_ENCRYPTION_KEY';
const KEYS = ['QODIQA_KEY_ENCRYPTION_KEY', TR_ENV, CP_ENV, 'QODIQA_TRANSPARENCY_KEYS_PATH', 'QODIQA_CHECKPOINT_KEYS_PATH', 'QODIQA_KMS_PROVIDER'];
const saved = {};
beforeAll(() => { for (const k of KEYS) saved[k] = process.env[k]; });
afterAll(() => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });
beforeEach(() => { for (const k of KEYS) delete process.env[k]; });

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f54-'));

function stores({ shared = SHARED, tr, cp, dir }) {
  jest.resetModules();
  process.env.QODIQA_TRANSPARENCY_KEYS_PATH = path.join(dir, 'transparency-keys.json');
  process.env.QODIQA_CHECKPOINT_KEYS_PATH = path.join(dir, 'checkpoint-keys.json');
  if (shared === null) delete process.env.QODIQA_KEY_ENCRYPTION_KEY; else process.env.QODIQA_KEY_ENCRYPTION_KEY = shared;
  if (tr) process.env[TR_ENV] = tr; else delete process.env[TR_ENV];
  if (cp) process.env[CP_ENV] = cp; else delete process.env[CP_ENV];
  require('../../../../services/secrets/secretsProvider')._clearCache();
  return { transparency: require('../transparencyKeyStore'), checkpoint: require('../../audit/checkpoint/checkpointKeyStore') };
}

describe('dedicated KEKs for the audit key stores', () => {
  test('SK-01 secretsProvider: shared by default, scoped when set, hard failure when malformed', () => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = SHARED;
    const sp = require('../../../../services/secrets/secretsProvider');
    sp._clearCache();
    expect(sp.getKeyEncryptionKey('transparency').equals(sp.getKeyEncryptionKey())).toBe(true);
    expect(sp.hasScopedKek('transparency')).toBe(false);
    process.env[TR_ENV] = TR; process.env[CP_ENV] = CP;
    expect(sp.getKeyEncryptionKey('transparency').toString('hex')).toBe(TR);
    expect(sp.getKeyEncryptionKey('audit-checkpoint').toString('hex')).toBe(CP);
    expect(sp.getKeyEncryptionKey().toString('hex')).toBe(SHARED);                 // the shared KEK is untouched
    expect(sp.hasScopedKek('transparency')).toBe(true);
    expect(sp.kekEnvName('transparency')).toBe(TR_ENV);
    expect(sp.kekEnvName()).toBe('QODIQA_KEY_ENCRYPTION_KEY');
    process.env[TR_ENV] = 'xyz';
    expect(() => sp.getKeyEncryptionKey('transparency')).toThrow(/64 hex/);
    process.env[TR_ENV] = '0'.repeat(64);
    expect(() => sp.getKeyEncryptionKey('transparency')).toThrow(/trivial/);
    process.env[TR_ENV] = 'ab'.repeat(32);
    expect(() => sp.getKeyEncryptionKey('transparency')).toThrow(/trivial/);
    expect(() => sp.getKeyEncryptionKey('nonsense')).toThrow(/unknown key-encryption scope/);
    process.env[TR_ENV] = '';                                                       // an empty value is "unset"
    expect(sp.getKeyEncryptionKey('transparency').toString('hex')).toBe(SHARED);
  });

  test('SK-02 each key file is encrypted, sealed and fingerprinted under its own KEK, and opens only under it', () => {
    const dir = tmp();
    const s1 = stores({ tr: TR, cp: CP, dir });
    s1.transparency.rotateKey();
    s1.checkpoint.ensureActiveKey();
    const { computeKekFingerprint } = require('../../../../services/artifact/keyEncryption');
    const trFile = JSON.parse(fs.readFileSync(process.env.QODIQA_TRANSPARENCY_KEYS_PATH, 'utf8'));
    const cpFile = JSON.parse(fs.readFileSync(process.env.QODIQA_CHECKPOINT_KEYS_PATH, 'utf8'));
    expect(trFile.kekFingerprint).toBe(computeKekFingerprint('transparency'));
    expect(cpFile.kekFingerprint).toBe(computeKekFingerprint('audit-checkpoint'));
    expect(trFile.kekFingerprint).not.toBe(cpFile.kekFingerprint);
    expect(trFile.kekFingerprint).not.toBe(computeKekFingerprint());              // not the shared KEK's
    // both reload under the same scoped KEKs, the keys decrypt and sign
    const s2 = stores({ tr: TR, cp: CP, dir });
    expect(() => s2.transparency.getActiveKey()).not.toThrow();
    expect(() => s2.checkpoint.getActiveKey()).not.toThrow();
    // the shared KEK is not enough to open either, and neither is the other store's KEK
    const wrongShared = stores({ dir });
    expect(() => wrongShared.transparency.getActiveKey()).toThrow(/KEK_FINGERPRINT_MISMATCH/);
    expect(() => wrongShared.checkpoint.getActiveKey()).toThrow(/KEK_FINGERPRINT_MISMATCH/);
    const swapped = stores({ tr: CP, cp: TR, dir });
    expect(() => swapped.transparency.getActiveKey()).toThrow(/KEK_FINGERPRINT_MISMATCH/);
    expect(() => swapped.checkpoint.getActiveKey()).toThrow(/KEK_FINGERPRINT_MISMATCH/);
  });

  test('SK-03 a changed, removed or added scoped KEK fails closed and names the variable in use', () => {
    const dir = tmp();
    stores({ tr: TR, dir }).transparency.rotateKey();
    expect(() => stores({ tr: OTHER, dir }).transparency.getActiveKey()).toThrow(new RegExp(`KEK_FINGERPRINT_MISMATCH: the configured ${TR_ENV} does not match`));
    expect(() => stores({ dir }).transparency.getActiveKey()).toThrow(new RegExp(`set ${TR_ENV} again`));      // removed: the hint says what to restore
    const dir2 = tmp();
    stores({ dir: dir2 }).transparency.rotateKey();                                                             // created under the shared KEK
    expect(() => stores({ tr: TR, dir: dir2 }).transparency.getActiveKey()).toThrow(new RegExp(`the configured ${TR_ENV} does not match`));   // added later
  });

  test('SK-04 nothing configured: the store refuses before creating any key', () => {
    const dir = tmp();
    const s = stores({ shared: null, dir });
    expect(() => s.transparency.rotateKey()).toThrow(/QODIQA_KEY_ENCRYPTION_KEY is not set/);
    expect(fs.existsSync(process.env.QODIQA_TRANSPARENCY_KEYS_PATH)).toBe(false);
    const withOnlyTr = stores({ shared: null, tr: TR, dir });                                                    // a scoped KEK alone serves that store, not the other
    expect(() => withOnlyTr.transparency.rotateKey()).not.toThrow();
    expect(() => withOnlyTr.checkpoint.ensureActiveKey()).toThrow(/QODIQA_KEY_ENCRYPTION_KEY is not set/);
    expect(fs.existsSync(process.env.QODIQA_CHECKPOINT_KEYS_PATH)).toBe(false);
  });

  test('SK-05 without scoped variables the stores use the shared KEK exactly as before', () => {
    const dir = tmp();
    stores({ dir }).transparency.rotateKey();
    const again = stores({ dir });
    expect(() => again.transparency.getActiveKey()).not.toThrow();
    const { computeKekFingerprint } = require('../../../../services/artifact/keyEncryption');
    const f = JSON.parse(fs.readFileSync(process.env.QODIQA_TRANSPARENCY_KEYS_PATH, 'utf8'));
    expect(f.kekFingerprint).toBe(computeKekFingerprint());
    expect(computeKekFingerprint('transparency')).toBe(computeKekFingerprint());
  });

  describe('SK-06 boot validation', () => {
    const { validateBoot } = require('../../../infra/config/bootValidator');
    const crypto = require('crypto');
    const base = () => {
      const dir = tmp();
      return {
        NODE_ENV: 'production', QODIQA_CLIENT_ID: 'acme-prod', QODIQA_KEY_ENCRYPTION_KEY: SHARED,
        QODIQA_EXECUTION_INVARIANT_SECRET: crypto.randomBytes(32).toString('hex'),
        QODIQA_TRANSPARENCY_KEYS_PATH: path.join(dir, 'transparency-keys.json'),
      };
    };
    const findingsFor = (env, variable) => {
      const r = validateBoot(env, { profile: 'prod' });
      return [...(r.fatal || []), ...(r.warnings || [])].filter((f) => f.variable === variable);
    };

    test('a malformed or trivial scoped KEK is refused in every profile', () => {
      for (const bad of ['xyz', '0'.repeat(64)]) {
        const f = findingsFor({ ...base(), [TR_ENV]: bad }, TR_ENV);
        expect(f.length).toBeGreaterThan(0);
      }
      expect(findingsFor({ ...base(), [CP_ENV]: 'abc' }, CP_ENV).length).toBeGreaterThan(0);
    });

    test('QODIQA_AUDIT_KEK_SEPARATION: off (default) is silent; warn reports sharing; enforce refuses it; three distinct KEKs pass enforce', () => {
      const env = base();
      expect(findingsFor(env, TR_ENV)).toEqual([]);
      expect(findingsFor({ ...env, QODIQA_AUDIT_KEK_SEPARATION: 'off' }, TR_ENV)).toEqual([]);
      const warn = validateBoot({ ...env, QODIQA_AUDIT_KEK_SEPARATION: 'warn' }, { profile: 'prod' });
      expect((warn.warnings || []).some((f) => f.variable === TR_ENV)).toBe(true);
      expect((warn.fatal || []).some((f) => f.variable === TR_ENV)).toBe(false);
      const enforce = validateBoot({ ...env, QODIQA_AUDIT_KEK_SEPARATION: 'enforce' }, { profile: 'prod' });
      expect((enforce.fatal || []).filter((f) => [TR_ENV, CP_ENV].includes(f.variable)).length).toBe(2);
      const distinct = validateBoot({ ...env, QODIQA_AUDIT_KEK_SEPARATION: 'enforce', [TR_ENV]: TR, [CP_ENV]: CP }, { profile: 'prod' });
      expect((distinct.fatal || []).filter((f) => [TR_ENV, CP_ENV].includes(f.variable))).toEqual([]);
      const equalShared = validateBoot({ ...env, QODIQA_AUDIT_KEK_SEPARATION: 'enforce', [TR_ENV]: SHARED, [CP_ENV]: CP }, { profile: 'prod' });
      expect((equalShared.fatal || []).some((f) => f.variable === TR_ENV && /equals QODIQA_KEY_ENCRYPTION_KEY/.test(f.message))).toBe(true);
      const equalEachOther = validateBoot({ ...env, QODIQA_AUDIT_KEK_SEPARATION: 'enforce', [TR_ENV]: TR, [CP_ENV]: TR }, { profile: 'prod' });
      expect((equalEachOther.fatal || []).some((f) => f.variable === CP_ENV && new RegExp(`equals ${TR_ENV}`).test(f.message))).toBe(true);
      expect((validateBoot({ ...env, QODIQA_AUDIT_KEK_SEPARATION: 'maybe' }, { profile: 'prod' }).fatal || []).some((f) => f.variable === 'QODIQA_AUDIT_KEK_SEPARATION')).toBe(true);
    });

    test('outside production the separation mode is not enforced', () => {
      const r = validateBoot({ ...base(), NODE_ENV: 'development', QODIQA_AUDIT_KEK_SEPARATION: 'enforce' }, { profile: 'dev' });
      expect((r.fatal || []).some((f) => f.variable === TR_ENV)).toBe(false);
    });
  });
});
