'use strict';

// the keystore MAC keyring behind every cross-process
// integrity check (consent cache, revocation and org-status pub/sub, org-status
// hash). Each test gets its own keyring file in a fresh temp directory.

const fs = require('fs');
const os = require('os');
const path = require('path');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

let ring;
let dir;
const ORIG = { MAC: process.env.QODIQA_MAC_KEYS_PATH, NODE_ENV: process.env.NODE_ENV };

beforeEach(() => {
  jest.resetModules();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-mackeyring-'));
  process.env.QODIQA_MAC_KEYS_PATH = path.join(dir, 'mac-keys.json');
  ring = require('../macKeyring');
});

afterEach(() => {
  if (ORIG.MAC === undefined) delete process.env.QODIQA_MAC_KEYS_PATH; else process.env.QODIQA_MAC_KEYS_PATH = ORIG.MAC;
  process.env.NODE_ENV = ORIG.NODE_ENV;
  fs.rmSync(dir, { recursive: true, force: true });
});

const P = () => ring.PURPOSES;

describe('macKeyring', () => {
  test('sign → verify round trip; tag is <kid>.<base64url HMAC-SHA256>', () => {
    const tag = ring.sign(P().REVOCATION, 'hello');
    expect(tag).toMatch(/^mk_[0-9]{8}_[0-9a-f]{8}\.[A-Za-z0-9_-]{43}$/);
    expect(ring.verify(P().REVOCATION, 'hello', tag)).toEqual({ ok: true, kid: tag.split('.')[0] });
  });

  test('a different message, a different purpose (domain separation), or a flipped MAC character fails BAD_MAC', () => {
    const tag = ring.sign(P().REVOCATION, 'hello');
    expect(ring.verify(P().REVOCATION, 'hellO', tag).reason).toBe('BAD_MAC');
    expect(ring.verify(P().ORG_STATUS, 'hello', tag).reason).toBe('BAD_MAC');
    const last = tag.at(-1) === 'A' ? 'B' : 'A';
    expect(ring.verify(P().REVOCATION, 'hello', tag.slice(0, -1) + last).reason).toBe('BAD_MAC');
  });

  test('missing, malformed and unknown-kid tags are refused with a reason', () => {
    expect(ring.verify(P().REVOCATION, 'x', undefined).reason).toBe('MISSING');
    expect(ring.verify(P().REVOCATION, 'x', '').reason).toBe('MISSING');
    expect(ring.verify(P().REVOCATION, 'x', 'no-dot-here').reason).toBe('MALFORMED');
    expect(ring.verify(P().REVOCATION, 'x', 'a'.repeat(64)).reason).toBe('MALFORMED'); // a v1 hex HMAC
    expect(ring.verify(P().REVOCATION, 'x', 'mk_20000101_deadbeef.AAAA').reason).toBe('UNKNOWN_KEY');
  });

  test('the keyring file holds no plaintext key material (keys are KEK-encrypted)', () => {
    ring.sign(P().CONSENT_CACHE, 'x');
    const doc = JSON.parse(fs.readFileSync(process.env.QODIQA_MAC_KEYS_PATH, 'utf8'));
    expect(doc.version).toBe(1);
    expect(doc.keys).toHaveLength(1);
    expect(doc.keys[0]).toMatchObject({ status: 'active' });
    expect(doc.keys[0].key).toBeUndefined();
    expect(typeof doc.keys[0].enc).toBe('object');
  });

  test('status() never returns key material', () => {
    const st = ring.status();
    expect(Object.keys(st).sort()).toEqual(['activeKid', 'path', 'verifiableKids']);
    expect(st.verifiableKids).toEqual([st.activeKid]);
  });

  test('rotate(): new tags use the new key; tags from the previous key still verify; two rotations retire it', () => {
    const t0 = ring.sign(P().REVOCATION, 'm');
    const r1 = ring.rotate({ by: 'test' });
    expect(r1.previousKid).toBe(t0.split('.')[0]);
    const t1 = ring.sign(P().REVOCATION, 'm');
    expect(t1.split('.')[0]).toBe(r1.activeKid);
    expect(ring.verify(P().REVOCATION, 'm', t0).ok).toBe(true); // previous: still verifiable
    ring.rotate({ by: 'test' });
    expect(ring.verify(P().REVOCATION, 'm', t1).ok).toBe(true);
    expect(ring.verify(P().REVOCATION, 'm', t0).reason).toBe('UNKNOWN_KEY'); // retired
    // retired keys are kept in the file (never deleted), just no longer loaded
    const doc = JSON.parse(fs.readFileSync(process.env.QODIQA_MAC_KEYS_PATH, 'utf8'));
    expect(doc.keys.map((k) => k.status)).toEqual(['retired', 'previous', 'active']);
  });

  test('another node rotating the shared file: an unknown kid triggers a reload and then verifies', () => {
    ring.sign(P().REVOCATION, 'm'); // node A loads the ring
    jest.isolateModules(() => {     // node B, same file, rotates and signs
      const other = require('../macKeyring');
      other.rotate({ by: 'node-b' });
      const tagB = other.sign(P().REVOCATION, 'm');
      expect(ring.verify(P().REVOCATION, 'm', tagB).ok).toBe(true);
    });
  });

  test('init() creates once and never overwrites', () => {
    const a = ring.init();
    expect(a.created).toBe(true);
    const before = fs.readFileSync(process.env.QODIQA_MAC_KEYS_PATH, 'utf8');
    expect(ring.init()).toEqual({ created: false, path: process.env.QODIQA_MAC_KEYS_PATH });
    expect(fs.readFileSync(process.env.QODIQA_MAC_KEYS_PATH, 'utf8')).toBe(before);
  });

  test('production never generates a keyring on first use: sign() throws MAC_KEYRING_MISSING', () => {
    process.env.NODE_ENV = 'production';
    expect(() => ring.sign(P().REVOCATION, 'm')).toThrow(expect.objectContaining({ code: 'MAC_KEYRING_MISSING' }));
    expect(fs.existsSync(process.env.QODIQA_MAC_KEYS_PATH)).toBe(false);
  });

  test('a keyring encrypted under a different KEK cannot be loaded (fails closed, never silently re-keyed)', () => {
    ring.init();
    const saved = process.env.QODIQA_KEY_ENCRYPTION_KEY;
    try {
      process.env.QODIQA_KEY_ENCRYPTION_KEY = '1'.repeat(64);
      jest.resetModules();
      const other = require('../macKeyring');
      expect(() => other.sign(P().REVOCATION, 'm')).toThrow();
    } finally {
      process.env.QODIQA_KEY_ENCRYPTION_KEY = saved;
    }
  });

  test('keyringPath(): explicit path wins; otherwise mac-keys.json beside QODIQA_KEYS_PATH', () => {
    expect(ring.keyringPath()).toBe(process.env.QODIQA_MAC_KEYS_PATH);
    delete process.env.QODIQA_MAC_KEYS_PATH;
    expect(ring.keyringPath()).toBe(path.join(path.dirname(process.env.QODIQA_KEYS_PATH), 'mac-keys.json'));
  });
});

describe('the key file is created at boot, never by a request path', () => {
  test('without the harness hook, sign() on a missing file refuses (MAC_KEYRING_MISSING) and writes nothing; init() is the only creator', () => {
    const hook = globalThis.__qodiqaMacKeyringAutoProvision;
    delete globalThis.__qodiqaMacKeyringAutoProvision;
    try {
      ring._resetForTest();
      expect(() => ring.sign(ring.PURPOSES.SAML_STATE || Object.values(ring.PURPOSES)[0], 'm')).toThrow(expect.objectContaining({ code: 'MAC_KEYRING_MISSING' }));
      expect(fs.existsSync(process.env.QODIQA_MAC_KEYS_PATH)).toBe(false);
      expect(ring.init().created).toBe(true);
      expect(typeof ring.sign(Object.values(ring.PURPOSES)[0], 'm')).toBe('string');
    } finally { globalThis.__qodiqaMacKeyringAutoProvision = hook; }
  });
  test('the hook is never honoured in production', () => {
    const hook = globalThis.__qodiqaMacKeyringAutoProvision; let calls = 0;
    globalThis.__qodiqaMacKeyringAutoProvision = () => { calls += 1; };
    process.env.NODE_ENV = 'production';
    try { ring._resetForTest(); expect(() => ring.sign(Object.values(ring.PURPOSES)[0], 'm')).toThrow(/missing/i); expect(calls).toBe(0); }
    finally { globalThis.__qodiqaMacKeyringAutoProvision = hook; }
  });
});
