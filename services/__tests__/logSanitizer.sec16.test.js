'use strict';

/**
 * — the sanitizer recognised generic token shapes (JWT, Bearer, PEM) but not
 * the credentials QODIQA itself issues, so one in free text (an error message, a URL, a misplaced field) reached the
 * logs. These are recognised by VALUE now.
 *
 *   KF-01 RBAC operator (ok_), signing-identity (sk_) and webhook (whsec_) keys are redacted in free text
 *   KF-02 portal session tokens (pt_<b64url>.<hex>) are redacted
 *   KF-03 Ed25519 private keys as raw PKCS#8 DER (base64 and hex, no PEM armour) are redacted
 *   KF-04 URL userinfo passwords (postgres://u:pw@, redis://:pw@) are redacted, the rest of the URL kept
 *   KF-05 QODIQA credential field names (adminKey, opsToken, pgPassword, …) are redacted by field name
 *   KF-06 controls: hashes, key ids, a near-miss key (63 hex) and a URL without userinfo are untouched
 *   KF-07 with token/crypto scanning explicitly off (non-production only), the value patterns are off too
 * KF-08 AI-provider keys of the `sk-` family are redacted wherever they appear:
 *         OpenAI legacy / project / service-account / admin, Anthropic api03 — in free text, URLs and error messages
 *   KF-09 controls: truncated/abbreviated keys, kebab-case words, other prefixes and a QODIQA sk_ key's own handling
 */

const crypto = require('crypto');

function load(env = {}) {
  jest.resetModules();
  const saved = {};
  for (const [k, v] of Object.entries(env)) { saved[k] = process.env[k]; process.env[k] = v; }
  const m = require('../logSanitizer');
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  return m;
}

const hex = (n) => crypto.randomBytes(n).toString('hex');
const der = () => crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' });

describe('QODIQA key formats', () => {
  const { sanitize } = load();

  test('KF-01 ok_/sk_/whsec_ keys in free text', () => {
    const keys = [`ok_${hex(32)}`, `sk_${hex(32)}`, `whsec_${hex(32)}`];
    const out = sanitize({ message: `rejected ${keys[0]}; issued ${keys[1]} (secret ${keys[2]})` }).message;
    for (const k of keys) expect(out).not.toContain(k);
    expect(out).toMatch(/^rejected \S+; issued \S+ \(secret \S+\)$/);
  });

  test('KF-02 portal session token', () => {
    const tok = `pt_${Buffer.from(JSON.stringify({ sub: 'u', exp: 1 })).toString('base64url')}.${hex(32)}`;
    expect(sanitize({ note: `cookie ${tok}` }).note).not.toContain(tok);
  });

  test('KF-03 Ed25519 PKCS#8 DER private key, base64 and hex', () => {
    const k = der();
    const out = sanitize({ b64: `key=${k.toString('base64')}`, hex: k.toString('hex') });
    expect(out.b64).not.toContain(k.toString('base64'));
    expect(out.hex).not.toContain(k.toString('hex').slice(32));
  });

  test('KF-04 URL userinfo passwords', () => {
    const out = sanitize({ a: 'connect postgres://qodiqa_app:S3cr3t-pw@db:5432/qodiqa failed', b: 'redis://:pw-123456@cache:6379' });
    expect(out.a).not.toContain('S3cr3t-pw');
    expect(out.a).toContain('postgres://qodiqa_app:');
    expect(out.a).toContain('@db:5432/qodiqa failed');
    expect(out.b).not.toContain('pw-123456');
  });

  test('KF-05 credential field names', () => {
    const out = sanitize({ adminKey: 'x1', opsToken: 'x2', pgPassword: 'x3', hmacKey: 'x4', portalToken: 'x5' });
    for (const v of Object.values(out)) expect(v).toBe('[REDACTED]');
  });

  test('KF-06 controls are untouched', () => {
    const input = { sha: `sha256:${hex(32)}`, keyId: 'default:key_v1', near: `ok_${'a'.repeat(63)}`, url: 'https://example.test/path?q=1', kid: 'mk_20261004' };
    expect(sanitize(input)).toEqual(input);
  });
});

describe('AI-provider key formats (sk- family)', () => {
  const { sanitize } = load();
  const b62 = (n) => { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; let o = ''; const r = crypto.randomBytes(n); for (let i = 0; i < n; i++) o += a[r[i] % 62]; return o; };
  // generated so every key mixes digits and upper case, as real keys do
  const key = (prefix, n) => `${prefix}A1${b62(n - 2)}`;
  const KEYS = {
    'OpenAI legacy (sk-<48>)':      key('sk-', 48),
    'OpenAI project (sk-proj-)':    `sk-proj-${key('', 60)}_${b62(40)}-${b62(20)}`,
    'OpenAI service account':       `sk-svcacct-${key('', 90)}`,
    'OpenAI admin':                 `sk-admin-${key('', 70)}`,
    'Anthropic (sk-ant-api03-)':    `sk-ant-api03-${key('', 86)}-${b62(6)}AA`,
  };

  test.each(Object.entries(KEYS))('KF-08 %s is redacted in free text, a URL and an error message', (_n, k) => {
    const out = sanitize({
      message: `provider rejected key ${k} (401)`,
      url: `https://api.example.com/v1/chat?api_key=${k}&x=1`,
      error: `Error: Incorrect API key provided: ${k}.`,
    });
    for (const v of Object.values(out)) expect(v).not.toContain(k);
    expect(out.message).toBe('provider rejected key [TOKEN] (401)');
    expect(out.url).toMatch(/^https:\/\/api\.example\.com\/v1\/chat\?api_key=\[TOKEN\]&x=1$/);
  });

  test('KF-09 controls: truncated keys, kebab-case words and other prefixes are not touched', () => {
    const untouched = [
      'sk-abc...wxyz',                                   // dashboard-style abbreviation (not a credential)
      `sk-${'A1'.repeat(10)}`,                           // truncated: below the length floor
      'sk-learn-compatibility-layer-for-pipelines-and-more',  // lower-case kebab-case word
      'risk-Adjusted-portfolio-2026-annual-report-v2-final-x', // "sk" inside a word
      `pk-${key('', 48)}`,                               // a different (public-key) prefix
      `skx-${key('', 48)}`,                              // not the sk- prefix
    ];
    for (const t of untouched) expect(sanitize({ m: t }).m).toBe(t);
    // compatibility: the QODIQA sk_<64 hex> key keeps its own handling
    const own = `sk_${hex(32)}`;
    expect(sanitize({ m: `issued ${own}` }).m).toBe('issued [TOKEN]');
  });
});

describe('scanning switches', () => {
  test('KF-07 token/crypto scanning off (non-production) disables the value patterns', () => {
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'test';
    const { sanitize } = load({ LOG_SANITIZER_SCAN_TOKENS: 'false', LOG_SANITIZER_SCAN_CRYPTO: 'false' });
    process.env.NODE_ENV = prevEnv;
    const k = `ok_${hex(32)}`;
    expect(sanitize({ m: k }).m).toBe(k);
  });
});
