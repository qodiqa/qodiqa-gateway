'use strict';
const { PROVIDER_FIXTURE_KEYS } = require('../../../test/helpers/providerFixtureKeys'); // format-valid fake keys

jest.mock('../../logger', () => ({ emit: jest.fn() }));

// ── Helper to reload the module with specific env vars ────────────────────────
function loadConfig(env = {}) {
  jest.resetModules();
  const saved = {};
  const keys = [
    'OPENAI_API_KEY', 'OPENAI_TIMEOUT_MS',
    'ANTHROPIC_API_KEY', 'ANTHROPIC_TIMEOUT_MS', 'ANTHROPIC_MAX_TOKENS',
    'GEMINI_API_KEY', 'GEMINI_TIMEOUT_MS',
    'MISTRAL_API_KEY', 'MISTRAL_BASE_URL', 'MISTRAL_TIMEOUT_MS',
    'LLAMA_BASE_URL', 'LLAMA_API_KEY', 'LLAMA_TIMEOUT_MS',
    'LOCAL_BASE_URL', 'LOCAL_API_KEY', 'LOCAL_TIMEOUT_MS',
    'PROVIDER_FAILOVER_OPENAI', 'PROVIDER_FAILOVER_ANTHROPIC',
    'PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI', 'PROVIDER_ALLOWED_MODELS_EXTRA_ANTHROPIC',
    'PROVIDER_ALLOWED_MODELS_EXTRA_GEMINI', 'PROVIDER_ALLOWED_MODELS_EXTRA_MISTRAL',
    'PROVIDER_ALLOWED_MODELS_EXTRA_LLAMA', 'PROVIDER_ALLOWED_MODELS_EXTRA_LOCAL',
    'PROVIDER_DEFAULT_MODEL_OPENAI', 'PROVIDER_DEFAULT_MODEL_ANTHROPIC',
    'PROVIDER_DEFAULT_MODEL_GEMINI', 'PROVIDER_DEFAULT_MODEL_MISTRAL',
    'PROVIDER_DEFAULT_MODEL_LLAMA', 'PROVIDER_DEFAULT_MODEL_LOCAL',
  ];
  for (const k of keys) {
    saved[k]        = process.env[k];
    process.env[k]  = env[k] !== undefined ? env[k] : '';
  }
  // Set explicitly provided keys
  for (const [k, v] of Object.entries(env)) {
    process.env[k] = v;
  }
  const mod = require('../config');
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else                 process.env[k] = v;
  }
  return mod;
}

// ── getProviderConfig ─────────────────────────────────────────────────────────

describe('getProviderConfig', () => {
  test('returns null for unknown provider', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    expect(getProviderConfig('unknown')).toBeNull();
  });

  test('returns config object for known provider', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    const cfg = getProviderConfig('openai');
    expect(cfg).not.toBeNull();
    expect(cfg.baseUrl).toBe('https://api.openai.com/v1');
    expect(cfg.local).toBe(false);
  });

  test('openai enabled when OPENAI_API_KEY set', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    expect(getProviderConfig('openai').enabled).toBe(true);
  });

  test('openai disabled when OPENAI_API_KEY absent', () => {
    const { getProviderConfig } = loadConfig({});
    expect(getProviderConfig('openai').enabled).toBe(false);
  });

  test('anthropic enabled when ANTHROPIC_API_KEY set', () => {
    const { getProviderConfig } = loadConfig({ ANTHROPIC_API_KEY: PROVIDER_FIXTURE_KEYS.anthropic });
    expect(getProviderConfig('anthropic').enabled).toBe(true);
  });

  test('gemini enabled when GEMINI_API_KEY set', () => {
    const { getProviderConfig } = loadConfig({ GEMINI_API_KEY: PROVIDER_FIXTURE_KEYS.gemini });
    expect(getProviderConfig('gemini').enabled).toBe(true);
  });

  test('mistral enabled when MISTRAL_API_KEY set', () => {
    const { getProviderConfig } = loadConfig({ MISTRAL_API_KEY: PROVIDER_FIXTURE_KEYS.mistral });
    expect(getProviderConfig('mistral').enabled).toBe(true);
  });

  test('llama enabled when LLAMA_BASE_URL set', () => {
    const { getProviderConfig } = loadConfig({ LLAMA_BASE_URL: 'http://localhost:8080' });
    expect(getProviderConfig('llama').enabled).toBe(true);
  });

  test('local enabled when LOCAL_BASE_URL set', () => {
    const { getProviderConfig } = loadConfig({ LOCAL_BASE_URL: 'http://localhost:11434' });
    expect(getProviderConfig('local').enabled).toBe(true);
    expect(getProviderConfig('local').local).toBe(true);
  });

  test('local uses LOCAL_BASE_URL as baseUrl', () => {
    const { getProviderConfig } = loadConfig({ LOCAL_BASE_URL: 'http://localhost:11434' });
    expect(getProviderConfig('local').baseUrl).toBe('http://localhost:11434');
  });

  test('mistral uses custom MISTRAL_BASE_URL when set', () => {
    const { getProviderConfig } = loadConfig({
      MISTRAL_API_KEY: PROVIDER_FIXTURE_KEYS.mistral,
      MISTRAL_BASE_URL: 'https://custom.mistral.example.com/v1',
    });
    expect(getProviderConfig('mistral').baseUrl).toBe('https://custom.mistral.example.com/v1');
  });

  test('mistral uses default base URL when MISTRAL_BASE_URL not set', () => {
    const { getProviderConfig } = loadConfig({ MISTRAL_API_KEY: PROVIDER_FIXTURE_KEYS.mistral });
    expect(getProviderConfig('mistral').baseUrl).toBe('https://api.mistral.ai/v1');
  });

  test('timeoutMs defaults to 30000 when env var absent', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    expect(getProviderConfig('openai').timeoutMs).toBe(30_000);
  });

  test('timeoutMs reads from env var', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai, OPENAI_TIMEOUT_MS: '60000' });
    expect(getProviderConfig('openai').timeoutMs).toBe(60_000);
  });

  test('failoverProvider reads PROVIDER_FAILOVER_OPENAI', () => {
    const { getProviderConfig } = loadConfig({
      OPENAI_API_KEY:           PROVIDER_FIXTURE_KEYS.openai,
      PROVIDER_FAILOVER_OPENAI: 'anthropic',
    });
    expect(getProviderConfig('openai').failoverProvider).toBe('anthropic');
  });

  test('failoverProvider is null when not set', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    expect(getProviderConfig('openai').failoverProvider).toBeNull();
  });

  test('allowedModels is a Set', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    expect(getProviderConfig('openai').allowedModels).toBeInstanceOf(Set);
  });

  test('openai allowedModels contains expected models', () => {
    const { getProviderConfig } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    const models = getProviderConfig('openai').allowedModels;
    expect(models.has('gpt-4o')).toBe(true);
    expect(models.has('gpt-3.5-turbo')).toBe(true);
    expect(models.has('unknown-model')).toBe(false);
  });
});

// ── getEnabledProviders ───────────────────────────────────────────────────────

describe('getEnabledProviders', () => {
  test('returns empty array when no providers configured', () => {
    const { getEnabledProviders } = loadConfig({});
    expect(getEnabledProviders()).toEqual([]);
  });

  test('returns only enabled providers', () => {
    const { getEnabledProviders } = loadConfig({
      OPENAI_API_KEY:    PROVIDER_FIXTURE_KEYS.openai,
      ANTHROPIC_API_KEY: PROVIDER_FIXTURE_KEYS.anthropic,
    });
    const enabled = getEnabledProviders();
    expect(enabled).toContain('openai');
    expect(enabled).toContain('anthropic');
    expect(enabled).not.toContain('gemini');
    expect(enabled).not.toContain('mistral');
  });

  test('local provider included when LOCAL_BASE_URL set', () => {
    const { getEnabledProviders } = loadConfig({ LOCAL_BASE_URL: 'http://localhost:11434' });
    expect(getEnabledProviders()).toContain('local');
  });
});

// ── hasAnyProvider ────────────────────────────────────────────────────────────

describe('hasAnyProvider', () => {
  test('returns false when no providers configured', () => {
    const { hasAnyProvider } = loadConfig({});
    expect(hasAnyProvider()).toBe(false);
  });

  test('returns true when any provider is enabled', () => {
    const { hasAnyProvider } = loadConfig({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    expect(hasAnyProvider()).toBe(true);
  });

  test('returns true with only local provider', () => {
    const { hasAnyProvider } = loadConfig({ LOCAL_BASE_URL: 'http://localhost:11434' });
    expect(hasAnyProvider()).toBe(true);
  });
});

// ── additive-only model-allowlist extension ────────────────────────────

describe('PROVIDER_ALLOWED_MODELS_EXTRA_<NAME>', () => {
  test('built-in models remain accepted with no extension configured', () => {
    const { getProviderConfig } = loadConfig({});
    const models = getProviderConfig('openai').allowedModels;
    expect(models.has('gpt-4o')).toBe(true);
    expect(models.has('gpt-3.5-turbo')).toBe(true);
  });

  test('an env-added model is accepted in addition to the built-ins', () => {
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: 'gpt-5' });
    const models = getProviderConfig('openai').allowedModels;
    expect(models.has('gpt-5')).toBe(true);
    expect(models.has('gpt-4o')).toBe(true); // built-in still present
  });

  test('multiple comma-separated added models all work', () => {
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: 'gpt-5,gpt-5-mini,gpt-5-nano' });
    const models = getProviderConfig('openai').allowedModels;
    expect(models.has('gpt-5')).toBe(true);
    expect(models.has('gpt-5-mini')).toBe(true);
    expect(models.has('gpt-5-nano')).toBe(true);
  });

  test('entries are trimmed and empty entries (e.g. a trailing comma) are dropped', () => {
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: ' gpt-5 , , gpt-5-mini,' });
    const models = getProviderConfig('openai').allowedModels;
    expect(models.has('gpt-5')).toBe(true);
    expect(models.has('gpt-5-mini')).toBe(true);
    expect(models.has('')).toBe(false);
    expect(models.has(' gpt-5 ')).toBe(false);
  });

  test('built-in models cannot be removed via env configuration', () => {
    // Setting an extension to a value that shares nothing with the built-ins
    // must not shrink the built-in set — every original entry survives.
    const BUILT_IN_OPENAI = ['gpt-4', 'gpt-4-turbo', 'gpt-4-turbo-preview', 'gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo', 'gpt-3.5-turbo-16k'];
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: 'gpt-5' });
    const models = getProviderConfig('openai').allowedModels;
    for (const m of BUILT_IN_OPENAI) expect(models.has(m)).toBe(true);
  });

  test('an attempted removal/negation is ignored — the token is added inertly, the target survives', () => {
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: '-gpt-4,!gpt-4o' });
    const models = getProviderConfig('openai').allowedModels;
    // The real models are completely unaffected...
    expect(models.has('gpt-4')).toBe(true);
    expect(models.has('gpt-4o')).toBe(true);
    // ...and the malformed-looking tokens are themselves just harmless,
    // never-matched additional entries (there is no removal syntax at all).
    expect(models.has('-gpt-4')).toBe(true);
    expect(models.has('!gpt-4o')).toBe(true);
  });

  test('malformed extension configuration fails safe: an oversized entry is dropped, not accepted', () => {
    const oversized = 'x'.repeat(200);
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: `${oversized},gpt-5` });
    const models = getProviderConfig('openai').allowedModels;
    expect(models.has(oversized)).toBe(false);
    expect(models.has('gpt-5')).toBe(true); // the rest of the list still parses
  });

  test('malformed extension configuration fails safe: a control character drops the entry', () => {
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: 'gpt-5\x01evil,gpt-5' });
    const models = getProviderConfig('openai').allowedModels;
    expect([...models].some((m) => m.includes('\x01'))).toBe(false);
    expect(models.has('gpt-5')).toBe(true);
  });

  test('an empty/missing extension leaves the built-in allowlist unchanged', () => {
    const withExtra    = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: '' }).getProviderConfig('openai').allowedModels;
    const withoutExtra = loadConfig({}).getProviderConfig('openai').allowedModels;
    expect([...withExtra].sort()).toEqual([...withoutExtra].sort());
  });

  test('unrelated providers are not affected by another provider\'s extension', () => {
    const { getProviderConfig } = loadConfig({ PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI: 'gpt-5' });
    expect(getProviderConfig('anthropic').allowedModels.has('gpt-5')).toBe(false);
    expect(getProviderConfig('gemini').allowedModels.has('gpt-5')).toBe(false);
  });

  test('a configured extension is a no-op for a provider whose built-in allowlist is empty (unrestricted)', () => {
    const { getProviderConfig } = loadConfig({
      LLAMA_BASE_URL: 'http://localhost:8080',
      PROVIDER_ALLOWED_MODELS_EXTRA_LLAMA: 'llama3.2',
    });
    const cfg = getProviderConfig('llama');
    // Still unrestricted (empty Set), not narrowed to only the "extension".
    expect(cfg.allowedModels.size).toBe(0);
  });

  test('no model-validation bypass: an extension-added model is still validated by the single authoritative validator', () => {
    const saved = process.env.PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI;
    process.env.PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI = 'gpt-5';
    let results;
    // jest.isolateModules() guarantees ../config and ../modelValidation are
    // both required fresh, in the same isolated registry, so
    // modelValidation.js's own `require('./config')` sees the extension.
    jest.isolateModules(() => {
      const { validateModel } = require('../modelValidation');
      results = {
        added:   validateModel('openai', 'gpt-5'),
        unknown: validateModel('openai', 'gpt-5-EXTRA-UNKNOWN'),
      };
    });
    if (saved === undefined) delete process.env.PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI;
    else                     process.env.PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI = saved;
    expect(results.added).toEqual({ ok: true });
    expect(results.unknown).toEqual({ ok: false, code: 'PROVIDER_MODEL_NOT_ALLOWED' });
  });
});

// ── configurable default model ─────────────────────────────────────────

describe('PROVIDER_DEFAULT_MODEL_<NAME>', () => {
  test('openai keeps its built-in default (gpt-3.5-turbo) unchanged when unconfigured', () => {
    const { resolveDefaultModel } = loadConfig({});
    expect(resolveDefaultModel('openai')).toBe('gpt-3.5-turbo');
  });

  test('anthropic/gemini/mistral have no built-in default (strict allowlists that do not contain gpt-3.5-turbo — model must be supplied explicitly)', () => {
    const { resolveDefaultModel } = loadConfig({});
    for (const provider of ['anthropic', 'gemini', 'mistral']) {
      expect(resolveDefaultModel(provider)).toBeNull();
    }
  });

  // llama/local keep the SAME built-in default as openai (gpt-3.5-turbo) —
  // not because it is a sensible guess about what those deployments serve,
  // but because their allowlist is EMPTY (unrestricted, see config.js's own
  // module doc comment): any non-empty model string was always accepted, so
  // this default was never actually incompatible for them. Confirmed
  // load-bearing by the acceptance suite (AT-085/086/087 omit `model`
  // against provider:'local' and require the request to reach dispatch) —
  // this is not a design choice this test enforces in isolation, it is
  // regression coverage for a real bug this exact test would have caught.
  // split from the pre-fix "llama/local keep gpt-3.5-turbo" test. llama is unchanged;
  // local no longer has a built-in default (an OpenAI model name sent to Ollama → 404 → misleading 503 that
  // counted against the breaker). Its default comes only from PROVIDER_DEFAULT_MODEL_LOCAL.
  test('llama keeps the built-in gpt-3.5-turbo default — its unrestricted allowlist means it was never incompatible', () => {
    const { resolveDefaultModel } = loadConfig({ LLAMA_BASE_URL: 'http://localhost:8080' });
    expect(resolveDefaultModel('llama')).toBe('gpt-3.5-turbo');
  });

  test('local has NO built-in default — never gpt-3.5-turbo — when PROVIDER_DEFAULT_MODEL_LOCAL is unset', () => {
    const { resolveDefaultModel } = loadConfig({ LOCAL_BASE_URL: 'http://localhost:11434' });
    expect(resolveDefaultModel('local')).toBeNull();
  });

  test('local default comes from PROVIDER_DEFAULT_MODEL_LOCAL', () => {
    const { resolveDefaultModel } = loadConfig({
      LOCAL_BASE_URL: 'http://localhost:11434',
      PROVIDER_DEFAULT_MODEL_LOCAL: 'qwen2.5:7b',
    });
    expect(resolveDefaultModel('local')).toBe('qwen2.5:7b');
  });

  test('an enabled local provider with no default emits PROVIDER_DEFAULT_MODEL_UNSET naming the env var', () => {
    loadConfig({ LOCAL_BASE_URL: 'http://localhost:11434' });
    const { emit } = require('../../logger'); // the mock instance of the registry loadConfig just used
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_DEFAULT_MODEL_UNSET',
      expect.objectContaining({ provider: 'local', envVar: 'PROVIDER_DEFAULT_MODEL_LOCAL' }));
  });

  test('no PROVIDER_DEFAULT_MODEL_UNSET warning once PROVIDER_DEFAULT_MODEL_LOCAL is set', () => {
    loadConfig({ LOCAL_BASE_URL: 'http://localhost:11434', PROVIDER_DEFAULT_MODEL_LOCAL: 'qwen2.5:7b' });
    const { emit } = require('../../logger');
    expect(emit).not.toHaveBeenCalledWith('WARN', 'PROVIDER_DEFAULT_MODEL_UNSET', expect.anything());
  });

  test('PROVIDER_DEFAULT_MODEL_OPENAI overrides the built-in default', () => {
    const { resolveDefaultModel } = loadConfig({ PROVIDER_DEFAULT_MODEL_OPENAI: 'gpt-4o-mini' });
    expect(resolveDefaultModel('openai')).toBe('gpt-4o-mini');
  });

  test('PROVIDER_DEFAULT_MODEL_ANTHROPIC configures a default where none existed before', () => {
    const { resolveDefaultModel } = loadConfig({ PROVIDER_DEFAULT_MODEL_ANTHROPIC: 'claude-3-5-haiku-20241022' });
    expect(resolveDefaultModel('anthropic')).toBe('claude-3-5-haiku-20241022');
  });

  test('a malformed default override is dropped, falling back to the built-in value', () => {
    const oversized = 'x'.repeat(200);
    const { resolveDefaultModel } = loadConfig({ PROVIDER_DEFAULT_MODEL_OPENAI: oversized });
    expect(resolveDefaultModel('openai')).toBe('gpt-3.5-turbo');
  });

  test('resolveDefaultModel returns null for an unknown provider', () => {
    const { resolveDefaultModel } = loadConfig({});
    expect(resolveDefaultModel('not-a-real-provider')).toBeNull();
  });

  test('resolveDefaultModel is deterministic — repeated calls agree (pure function, no hidden state)', () => {
    const { resolveDefaultModel } = loadConfig({ PROVIDER_DEFAULT_MODEL_OPENAI: 'gpt-4o' });
    expect(resolveDefaultModel('openai')).toBe(resolveDefaultModel('openai'));
  });

  test('a configured default that is NOT a member of its own effective allowlist fails the module load (fail-closed)', () => {
    jest.resetModules();
    const saved = process.env.PROVIDER_DEFAULT_MODEL_OPENAI;
    process.env.PROVIDER_DEFAULT_MODEL_OPENAI = 'not-a-real-model';
    expect(() => require('../config')).toThrow(/PROVIDER_CONFIG_INVALID/);
    if (saved === undefined) delete process.env.PROVIDER_DEFAULT_MODEL_OPENAI;
    else                     process.env.PROVIDER_DEFAULT_MODEL_OPENAI = saved;
    jest.resetModules();
  });

  test('interaction: a default can resolve to a model added via the allowlist extension, not just a built-in', () => {
    const { resolveDefaultModel, getProviderConfig } = loadConfig({
      PROVIDER_ALLOWED_MODELS_EXTRA_ANTHROPIC: 'claude-custom-org-model',
      PROVIDER_DEFAULT_MODEL_ANTHROPIC:        'claude-custom-org-model',
    });
    expect(resolveDefaultModel('anthropic')).toBe('claude-custom-org-model');
    expect(getProviderConfig('anthropic').allowedModels.has('claude-custom-org-model')).toBe(true);
  });

  test('a provider with an empty (unrestricted) allowlist accepts any non-empty configured default, unchecked against a catalog', () => {
    const { resolveDefaultModel } = loadConfig({
      LLAMA_BASE_URL: 'http://localhost:8080',
      PROVIDER_DEFAULT_MODEL_LLAMA: 'llama3.2',
    });
    expect(resolveDefaultModel('llama')).toBe('llama3.2');
  });
});

// (BOOT-RULES.md section 3, decision D-E): a provider is enabled only by a key/URL
// that passes the shared credential rules — never by a merely non-empty value.
describe('provider enablement requires a valid, non-placeholder credential', () => {
  test.each([
    ['openai', 'OPENAI_API_KEY', 'sk-test'],
    ['openai', 'OPENAI_API_KEY', 'sk-your-api-key-here-0000000000000000000000'],
    ['openai', 'OPENAI_API_KEY', 'REPLACE_WITH_OPENAI_KEY'],
    ['anthropic', 'ANTHROPIC_API_KEY', 'changeme'],
    ['gemini', 'GEMINI_API_KEY', 'placeholder-gemini-key-00000000000000'],
    ['mistral', 'MISTRAL_API_KEY', 'your-mistral-key'],
  ])('%s stays disabled for placeholder value in %s', (provider, variable, value) => {
    const { getProviderConfig, getEnabledProviders } = loadConfig({ [variable]: value });
    expect(getProviderConfig(provider).enabled).toBe(false);
    expect(getEnabledProviders()).not.toContain(provider);
  });

  test.each([
    ['openai', 'OPENAI_API_KEY', 'not-an-openai-key-format-000000000000000000'],
    ['openai', 'OPENAI_API_KEY', 'sk-short'],
    ['anthropic', 'ANTHROPIC_API_KEY', 'sk-w2-fixture-openai-' + 'a'.repeat(24)], // openai shape, not sk-ant-
    ['gemini', 'GEMINI_API_KEY', 'too-short'],
    ['mistral', 'MISTRAL_API_KEY', 'has-dashes-which-mistral-keys-do-not-have'],
  ])('%s stays disabled for malformed value in %s', (provider, variable, value) => {
    const { getProviderConfig } = loadConfig({ [variable]: value });
    expect(getProviderConfig(provider).enabled).toBe(false);
  });

  test.each([
    ['llama', 'LLAMA_BASE_URL', 'ftp://169.254.169.254/latest/meta-data/'],
    ['local', 'LOCAL_BASE_URL', 'file:///etc/passwd'],
    ['local', 'LOCAL_BASE_URL', 'not a url'],
  ])('%s stays disabled for non-http(s) base URL', (provider, variable, value) => {
    const { getProviderConfig } = loadConfig({ [variable]: value });
    expect(getProviderConfig(provider).enabled).toBe(false);
  });

  test.each(['openai', 'anthropic', 'gemini', 'mistral'])('%s is enabled by a format-valid fixture key', (provider) => {
    const variable = { openai: 'OPENAI_API_KEY', anthropic: 'ANTHROPIC_API_KEY', gemini: 'GEMINI_API_KEY', mistral: 'MISTRAL_API_KEY' }[provider];
    const { getProviderConfig } = loadConfig({ [variable]: PROVIDER_FIXTURE_KEYS[provider] });
    expect(getProviderConfig(provider).enabled).toBe(true);
  });
});
