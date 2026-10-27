'use strict';

/**
 * remediation — single authoritative model-allowlist validator.
 *
 * Covers:
 *   - validateModelAgainstConfig() as a pure function (no config.js needed)
 *   - validateModel() against the REAL config.js, so a passing test here
 *     is proof the production allowlist actually rejects/accepts as expected
 * - the full negative-input matrix called out in the remediation:
 *     unknown, empty, null, undefined, whitespace-only, oversized,
 *     malformed/injected, Unicode lookalikes, provider-alias attempts,
 *     and case variants.
 */

const { validateModel, validateModelAgainstConfig, MAX_MODEL_LENGTH } = require('../modelValidation');
const { getProviderConfig } = require('../config');

// ── validateModelAgainstConfig — pure function, synthetic configs ──────────────

describe('validateModelAgainstConfig', () => {
  const restrictedConfig = { allowedModels: new Set(['model-a', 'model-b']) };
  const unrestrictedConfig = { allowedModels: new Set() };

  test('accepts a model present in the allowlist', () => {
    expect(validateModelAgainstConfig(restrictedConfig, 'model-a')).toEqual({ ok: true });
  });

  test('rejects a model absent from the allowlist', () => {
    expect(validateModelAgainstConfig(restrictedConfig, 'model-z'))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('empty allowlist (unrestricted) accepts any well-formed model', () => {
    expect(validateModelAgainstConfig(unrestrictedConfig, 'any-deployment-specific-name')).toEqual({ ok: true });
  });

  test.each([
    ['null', null],
    ['undefined', undefined],
    ['empty string', ''],
    ['number', 42],
    ['object', { model: 'model-a' }],
    ['array', ['model-a']],
    ['boolean', true],
  ])('rejects non-string / empty model: %s', (_label, model) => {
    expect(validateModelAgainstConfig(restrictedConfig, model))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('rejects whitespace-only model', () => {
    expect(validateModelAgainstConfig(unrestrictedConfig, '    '))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('rejects a model with leading/trailing whitespace rather than trimming it', () => {
    const padded = ' model-a ';
    expect(validateModelAgainstConfig(restrictedConfig, padded))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    // Confirms this is a real rejection, not a silent no-op: the trimmed
    // version is genuinely valid.
    expect(validateModelAgainstConfig(restrictedConfig, padded.trim())).toEqual({ ok: true });
  });

  test('rejects a model exceeding MAX_MODEL_LENGTH, even under an unrestricted allowlist', () => {
    const oversized = 'a'.repeat(MAX_MODEL_LENGTH + 1);
    expect(validateModelAgainstConfig(unrestrictedConfig, oversized))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('accepts a model exactly at MAX_MODEL_LENGTH under an unrestricted allowlist', () => {
    const exact = 'a'.repeat(MAX_MODEL_LENGTH);
    expect(validateModelAgainstConfig(unrestrictedConfig, exact)).toEqual({ ok: true });
  });

  test('rejects models containing control characters', () => {
    for (const model of [
      'model-a' + String.fromCharCode(0),      // NUL
      'model-a' + String.fromCharCode(9),      // TAB
      'model-a' + String.fromCharCode(10),     // LF
      'model-a' + String.fromCharCode(27) + '[0m', // ESC (ANSI injection attempt)
      'model-a' + String.fromCharCode(127),    // DEL
    ]) {
      expect(validateModelAgainstConfig(unrestrictedConfig, model))
        .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    }
  });

  test('rejects case-variants of an allowlisted model (case-sensitive)', () => {
    expect(validateModelAgainstConfig(restrictedConfig, 'MODEL-A'))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    expect(validateModelAgainstConfig(restrictedConfig, 'Model-A'))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('rejects a Unicode lookalike of an allowlisted model', () => {
    // 'model-а' where the final "a" is Cyrillic U+0430, not Latin U+0061.
    const lookalike = 'model-а';
    expect(lookalike).not.toBe('model-a');
    expect(validateModelAgainstConfig(restrictedConfig, lookalike))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('rejects injected/malformed identifiers against a restricted allowlist', () => {
    // These are well-formed strings (no control chars, no padding, under the
    // length cap) — under a RESTRICTED allowlist they are rejected simply
    // because they don't exact-match a real entry, same as any other unknown
    // model. (Under an UNRESTRICTED allowlist — llama/local — a string like
    // this is a legitimate deployment-specific model name and is accepted;
    // see the "empty allowlist" tests above.)
    for (const model of [
      '../../../etc/passwd',
      'model-a; DROP TABLE users;',
      '${jndi:ldap://evil.example/a}',
      '*',
      '<script>alert(1)</script>',
    ]) {
      expect(validateModelAgainstConfig(restrictedConfig, model))
        .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    }
  });

  test('rejects when config is null/undefined/missing allowedModels', () => {
    expect(validateModelAgainstConfig(null, 'model-a')).toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    expect(validateModelAgainstConfig(undefined, 'model-a')).toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    expect(validateModelAgainstConfig({}, 'model-a')).toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    expect(validateModelAgainstConfig({ allowedModels: ['model-a'] }, 'model-a'))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' }); // array, not a Set — malformed config
  });
});

// ── validateModel — against the REAL config.js (single source of truth) ────────

describe('validateModel (real config.js)', () => {
  test('every model in every provider allowlist in config.js validates as ok', () => {
    for (const provider of ['openai', 'anthropic', 'gemini', 'mistral']) {
      const { allowedModels } = getProviderConfig(provider);
      expect(allowedModels.size).toBeGreaterThan(0);
      for (const model of allowedModels) {
        expect(validateModel(provider, model)).toEqual({ ok: true });
      }
    }
  });

  test('a model from one provider is not valid for another (no cross-provider alias)', () => {
    const anthropicModel = [...getProviderConfig('anthropic').allowedModels][0];
    expect(validateModel('openai', anthropicModel)).toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('llama and local have empty (unrestricted) allowlists in config.js', () => {
    expect(getProviderConfig('llama').allowedModels.size).toBe(0);
    expect(getProviderConfig('local').allowedModels.size).toBe(0);
    expect(validateModel('llama', 'any-deployment-model')).toEqual({ ok: true });
    expect(validateModel('local', 'phi3')).toEqual({ ok: true });
  });

  test('unregistered provider name is rejected regardless of model', () => {
    expect(validateModel('totally-made-up-provider', 'gpt-4o'))
      .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('an unknown model is rejected for every known provider', () => {
    for (const provider of ['openai', 'anthropic', 'gemini', 'mistral']) {
      expect(validateModel(provider, 'definitely-not-a-real-model'))
        .toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    }
  });
});
