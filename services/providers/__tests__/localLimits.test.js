'use strict';

/**
 * Launch plan R-06 (LOCAL_MAX_TOKENS) and R-07 (PROVIDER_ALLOWED_MODELS_LOCAL): opt-in local-provider limits.
 * Unset → the outbound request body is exactly what it was before ({model, messages} / {model, messages, stream}).
 */

// The adapters resolve ./config lazily at call time, so every call that should see the isolated config must run
// inside the same jest.isolateModules scope (fn), with the env still applied.
function loadWith(env, fn = (m) => m) {
  const saved = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  let out;
  try {
    jest.isolateModules(() => {
      out = fn({ config: require('../config'), local: require('../local'), localStream: require('../local.stream') });
    });
  } finally {
    for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
  return out;
}

function specOf(mod) {
  return mod._spec; // test seam exported by local.js / local.stream.js
}

const BASE = { LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1', PROVIDER_DEFAULT_MODEL_LOCAL: 'llama3.2:1b' };
const BODY = { model: 'llama3.2:1b', messages: [{ role: 'user', content: 'hi' }] };

describe('local provider output cap (R-06)', () => {
  test('unset → maxTokens null and the outbound body carries no max_tokens (byte-identical to before)', () => {
    const { config, local, localStream } = loadWith({ ...BASE, LOCAL_MAX_TOKENS: undefined });
    expect(config.getProviderConfig('local').maxTokens).toBeNull();
    expect(specOf(local).transformRequest(BODY)).toEqual({ model: BODY.model, messages: BODY.messages });
    expect(specOf(localStream).transformRequest(BODY)).toEqual({ model: BODY.model, messages: BODY.messages, stream: true });
  });

  test('LOCAL_MAX_TOKENS=256 → max_tokens: 256 on normal and streaming requests', () => {
    const r = loadWith({ ...BASE, LOCAL_MAX_TOKENS: '256' }, ({ config, local, localStream }) => ({
      maxTokens: config.getProviderConfig('local').maxTokens,
      normal: specOf(local).transformRequest(BODY),
      stream: specOf(localStream).transformRequest(BODY),
    }));
    expect(r.maxTokens).toBe(256);
    expect(r.normal).toEqual({ model: BODY.model, messages: BODY.messages, max_tokens: 256 });
    expect(r.stream).toEqual({ model: BODY.model, messages: BODY.messages, stream: true, max_tokens: 256 });
  });

  test.each(['0', '-5', 'abc', '99999', '1.5', '8193'])('invalid LOCAL_MAX_TOKENS=%s → ignored (null), never a partial cap', (v) => {
    const { config, local } = loadWith({ ...BASE, LOCAL_MAX_TOKENS: v });
    expect(config.getProviderConfig('local').maxTokens).toBeNull();
    expect(specOf(local).transformRequest(BODY)).not.toHaveProperty('max_tokens');
  });

  test('parity with the production boot rule: every value config.js rejects, bootValidator refuses in production', () => {
    const { config } = loadWith(BASE);
    const { validateBoot } = require('../../../src/infra/config/bootValidator');
    for (const v of ['0', '1', '256', '8192', '8193', 'abc', ' 12 ', '1e3', '']) {
      const parsed = config.parseLocalMaxTokens(v);
      const boot = validateBoot({ NODE_ENV: 'development', LOCAL_BASE_URL: BASE.LOCAL_BASE_URL, LOCAL_MAX_TOKENS: v });
      const bootFlags = [...boot.fatal, ...boot.warnings].some((x) => x.variable === 'LOCAL_MAX_TOKENS');
      expect([v, bootFlags]).toEqual([v, !parsed.valid]);
    }
  });
});

describe('local provider model allowlist (R-07)', () => {
  test('unset → unrestricted (empty set), as before', () => {
    const { config } = loadWith({ ...BASE, PROVIDER_ALLOWED_MODELS_LOCAL: undefined });
    expect(config.getProviderConfig('local').allowedModels.size).toBe(0);
  });

  test('set → exactly that set; a default outside it fails module load', () => {
    const { config } = loadWith({ ...BASE, PROVIDER_ALLOWED_MODELS_LOCAL: 'llama3.2:1b, qwen2.5:1.5b-instruct' });
    expect([...config.getProviderConfig('local').allowedModels].sort()).toEqual(['llama3.2:1b', 'qwen2.5:1.5b-instruct']);
    expect(() => loadWith({ ...BASE, PROVIDER_ALLOWED_MODELS_LOCAL: 'qwen2.5:1.5b-instruct' })).toThrow(/PROVIDER_CONFIG_INVALID: local/);
  });

  test('a set allowlist refuses other models before dispatch (PROVIDER_MODEL_NOT_ALLOWED)', () => {
    const { validateModelAgainstConfig } = require('../modelValidation');
    const r = loadWith({ ...BASE, PROVIDER_ALLOWED_MODELS_LOCAL: 'llama3.2:1b' }, ({ config }) => config.getProviderConfig('local'));
    expect(validateModelAgainstConfig(r, 'llama3.2:1b')).toEqual({ ok: true });
    expect(validateModelAgainstConfig(r, 'mistral:7b')).toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });

  test('only separators → ignored (unrestricted), never an empty restrictive set that would refuse everything silently', () => {
    const { config } = loadWith({ ...BASE, PROVIDER_ALLOWED_MODELS_LOCAL: ' , ,' });
    expect(config.getProviderConfig('local').allowedModels.size).toBe(0);
  });
});
