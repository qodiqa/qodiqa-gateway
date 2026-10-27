'use strict';

const { loadConfig, DemoSignerConfigError } = require('../config');

const KEYS = { '/k/allowed': `sk_${'a'.repeat(32)}`, '/k/revoked': `sk_${'b'.repeat(32)}`, '/k/denied': `sk_${'c'.repeat(32)}` };

function fakeFs(files = KEYS, mode = 0o100600) {
  return {
    statSync: (p) => { if (!(p in files)) throw new Error('ENOENT'); return { isFile: () => true, mode }; },
    readFileSync: (p) => { if (!(p in files)) throw new Error('ENOENT'); return `${files[p]}\n`; },
  };
}

const ENABLED = {
  DEMO_SIGNER_ENABLED: 'true',
  DEMO_GATEWAY_URL: 'http://127.0.0.1:3000',
  DEMO_REDIS_URL: 'redis://127.0.0.1:56510',
  DEMO_IP_HASH_SECRET: 'x'.repeat(40),
  DEMO_KEY_FILE_ALLOWED: '/k/allowed',
  DEMO_KEY_FILE_REVOKED: '/k/revoked',
  DEMO_KEY_FILE_DENIED: '/k/denied',
};

function load(env, opts = {}) {
  return loadConfig(env, { fsImpl: fakeFs(opts.files, opts.mode), platform: opts.platform || 'linux' });
}

function problemsOf(env, opts) {
  try { load(env, opts); } catch (e) { expect(e).toBeInstanceOf(DemoSignerConfigError); return e.problems.join(' | '); }
  throw new Error('expected loadConfig to refuse');
}

describe('demo signer config (R-02)', () => {
  test('disabled by default; loads without keys and exposes no secrets', () => {
    const c = load({});
    expect(c.enabled).toBe(false);
    expect(c.scenarios).toEqual(['allowed', 'consent_revoked', 'policy_denied']);
    expect(c).toMatchObject({ perIpPerMin: 10, perIpPerDay: 50, globalPerMin: 30, maxPromptChars: 2000, chatPath: '/v1/ai/chat', provider: 'local' });
  });

  test('enabled with valid settings: keys loaded but non-enumerable (never serialised)', () => {
    const c = load(ENABLED);
    expect(c.enabled).toBe(true);
    expect(c.keys.allowed).toBe(KEYS['/k/allowed']);
    const serialised = JSON.stringify(c);
    expect(serialised).not.toMatch(/sk_/);
    expect(serialised).not.toContain('x'.repeat(40));
    expect(Object.keys(c)).not.toContain('keys');
  });

  test('refuses a global budget above 50/min (gateway per-identity ceilings)', () => {
    expect(problemsOf({ ...ENABLED, DEMO_GLOBAL_PER_MIN: '51' })).toMatch(/DEMO_GLOBAL_PER_MIN must be <= 50/);
  });

  test('refuses per-client minute budget above the global budget', () => {
    expect(problemsOf({ ...ENABLED, DEMO_GLOBAL_PER_MIN: '5', DEMO_PER_IP_PER_MIN: '6' })).toMatch(/must not exceed DEMO_GLOBAL_PER_MIN/);
  });

  test.each([['DEMO_PER_IP_PER_MIN', '0'], ['DEMO_PER_IP_PER_DAY', '-1'], ['DEMO_MAX_PROMPT_CHARS', 'abc'], ['DEMO_SIGNER_PORT', '1.5']])('refuses non-positive-integer %s=%s', (k, v) => {
    expect(problemsOf({ ...ENABLED, [k]: v })).toMatch(new RegExp(`${k} must be a positive integer`));
  });

  test('refuses a missing key file, a non-sk_ key and duplicate identities', () => {
    expect(problemsOf({ ...ENABLED, DEMO_KEY_FILE_DENIED: '/k/missing' })).toMatch(/DEMO_KEY_FILE_DENIED: key file not readable/);
    expect(problemsOf(ENABLED, { files: { ...KEYS, '/k/denied': 'ok_notasigningkey000000000' } })).toMatch(/does not contain a single sk_ signing key/);
    expect(problemsOf(ENABLED, { files: { ...KEYS, '/k/denied': KEYS['/k/allowed'] } })).toMatch(/distinct signing identity/);
  });

  test('POSIX: refuses key files readable by group/other; Windows mode bits are not evaluated', () => {
    expect(problemsOf(ENABLED, { mode: 0o100644 })).toMatch(/permissions must be 0600/);
    expect(load(ENABLED, { mode: 0o100644, platform: 'win32' }).enabled).toBe(true);
  });

  test('refuses short IP-hash secret, bad URLs, bad chat path, wildcard origin, oversized prompt cap', () => {
    const p = problemsOf({ ...ENABLED, DEMO_IP_HASH_SECRET: 'short', DEMO_GATEWAY_URL: 'ftp://x', DEMO_REDIS_URL: 'nope',
      DEMO_CHAT_PATH: '/v1/verify', DEMO_ALLOWED_ORIGIN: '*', DEMO_MAX_PROMPT_CHARS: '9000' });
    for (const re of [/DEMO_IP_HASH_SECRET/, /DEMO_GATEWAY_URL/, /DEMO_REDIS_URL/, /DEMO_CHAT_PATH/, /DEMO_ALLOWED_ORIGIN/, /DEMO_MAX_PROMPT_CHARS must be <= 8000/]) {
      expect(p).toMatch(re);
    }
  });
});
