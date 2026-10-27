'use strict';

// (BOOT-RULES.md §2–3, decision D-E): the shared credential rules used by
// the boot validator AND the provider registry — one definition of
// "placeholder", "weak secret" and "valid provider key".

const {
  isPlaceholder, secretProblems, providerKeyStatus, providerUrlStatus, isLoopbackHost, PROVIDER_KEY_FORMATS, HEX64,
} = require('./credentialRules');
const { PROVIDER_FIXTURE_KEYS } = require('../../../test/helpers/providerFixtureKeys');

describe('isPlaceholder', () => {
  test.each(['changeme', 'CHANGEME', '  secret ', 'password', 'test', '', '   '])('%j (whole value) is a placeholder', (v) => {
    expect(isPlaceholder(v)).toBe(true);
  });
  test.each(['changeme123', 'REPLACE_WITH_VAULT_SECRET_APP', 'my-placeholder-key', 'your-api-key-here', '<secret>', 'xxxx-1234', 'dummy-value', 'redacted'])(
    '%j (substring) is a placeholder — the earlier exact-match list let these through', (v) => {
      expect(isPlaceholder(v)).toBe(true);
    });
  test.each(['9f2c1a7e44b0d3', 'k7Q2-zX9m-Lp4r', 'w2-matrix-client'])('%j is not a placeholder', (v) => {
    expect(isPlaceholder(v)).toBe(false);
  });
  test('non-strings are not placeholders (absence is handled by the caller)', () => {
    expect(isPlaceholder(undefined)).toBe(false);
    expect(isPlaceholder(42)).toBe(false);
  });
});

describe('secretProblems', () => {
  test('a strong random value has no problems', () => {
    expect(secretProblems(require('crypto').randomBytes(32).toString('hex'))).toEqual([]);
  });
  test.each([
    ['short', 'Kx7mQ2', 32, ['too_short']],
    ['repeated', 'a'.repeat(40), 32, ['repeated']],
    ['2-char pattern', 'ab'.repeat(20), 32, ['pattern']],
    ['placeholder and short', 'changeme', 16, ['too_short', 'placeholder']],
    ['empty', '', 16, ['too_short', 'placeholder']],
  ])('%s → %j', (_n, value, minLength, expected) => {
    expect(secretProblems(value, { minLength })).toEqual(expected);
  });
  test('the minimum length is the caller\'s', () => {
    expect(secretProblems('Zq81mPx0Lk2vN7cW', { minLength: 16 })).toEqual([]);
    expect(secretProblems('Zq81mPx0Lk2vN7cW', { minLength: 32 })).toEqual(['too_short']);
  });
});

describe('providerKeyStatus — provider-specific format + placeholder detection (D-E)', () => {
  test.each(Object.keys(PROVIDER_KEY_FORMATS))('%s: the test fixture key is valid', (p) => {
    expect(providerKeyStatus(p, PROVIDER_FIXTURE_KEYS[p])).toBe('valid');
  });
  test.each(Object.keys(PROVIDER_KEY_FORMATS))('%s: absent when unset or empty', (p) => {
    expect(providerKeyStatus(p, undefined)).toBe('absent');
    expect(providerKeyStatus(p, '')).toBe('absent');
  });
  test.each([
    ['openai', 'sk-test'], ['openai', 'sk-your-key-here'], ['openai', 'sk-' + 'x'.repeat(40)], // built at runtime: no key-shaped literal for the secret scanner
    ['openai', 'sk-test-example-contract'], ['anthropic', 'sk-ant-REPLACE_WITH_KEY_aaaaaaaaaaaaaaaaaaaaaaaaaa'],
    ['gemini', 'your-gemini-api-key-goes-here-please'], ['mistral', 'changeme'],
  ])('%s %j → placeholder', (p, v) => {
    expect(providerKeyStatus(p, v)).toBe('placeholder');
  });
  test.each([
    ['openai', 'sk-short'], ['openai', 'pk-' + 'a'.repeat(40)], ['anthropic', 'sk-' + 'a'.repeat(40)],
    ['gemini', 'tooShort123'], ['mistral', 'has-dashes-' + 'a'.repeat(30)],
  ])('%s %j → invalid_format', (p, v) => {
    expect(providerKeyStatus(p, v)).toBe('invalid_format');
  });
  test('unknown provider is a programming error', () => {
    expect(() => providerKeyStatus('cohere', 'x')).toThrow(/unknown keyed provider/);
  });
});

describe('providerUrlStatus / isLoopbackHost', () => {
  test.each([['http://127.0.0.1:11434/v1', 'valid'], ['https://llm.example.org', 'valid'], ['ftp://x/y', 'invalid_url'],
    ['not a url', 'invalid_url'], ['', 'absent'], [undefined, 'absent']])('%j → %s', (v, s) => {
    expect(providerUrlStatus(v)).toBe(s);
  });
  test.each([['localhost', true], ['127.0.0.1', true], ['127.9.9.9', true], ['::1', true], ['[::1]', true],
    ['10.0.0.1', false], ['llm.internal', false]])('%s loopback=%s', (h, b) => {
    expect(isLoopbackHost(h)).toBe(b);
  });
});

test('HEX64 accepts exactly 64 hex characters', () => {
  expect(HEX64.test('a'.repeat(64))).toBe(true);
  expect(HEX64.test('A'.repeat(64))).toBe(true);
  expect(HEX64.test('a'.repeat(63))).toBe(false);
  expect(HEX64.test('g'.repeat(64))).toBe(false);
});
