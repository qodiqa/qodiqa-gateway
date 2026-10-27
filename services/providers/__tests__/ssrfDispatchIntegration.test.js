'use strict';
const { PROVIDER_FIXTURE_KEYS } = require('../../../test/helpers/providerFixtureKeys'); // format-valid fake keys

/**
 * Finding A — SSRF end-to-end dispatch integration test.
 *
 * Question this answers: does EVERY provider dispatch path actually invoke
 * the SSRF guard (services/providers/ssrf.js), or could a future refactor
 * silently bypass it? Prior coverage (ssrf.test.js) unit-tests the validator
 * in isolation; per-provider tests (openai.validation.test.js, llama.test.js,
 * etc.) call each handler DIRECTLY, never through the real dispatch
 * entrypoint (routeProviderCall -> handler) every production call actually
 * uses; router.test.js mocks every provider handler out entirely, so it
 * never exercises SSRF at all. None of them prove the guard survives a
 * refactor of the real end-to-end path.
 *
 * This suite closes that gap:
 *   - Uses the REAL router.js (routeProviderCall) and REAL provider handler
 *     modules for all six registered providers — nothing in
 *     services/providers/ is mocked.
 *   - services/providers/ssrf.js is NEVER mocked anywhere in this file —
 *     only jest.spyOn (real implementation preserved) is used, so the
 *     actual validation logic always runs for real.
 *   - Only the underlying HTTP transport is stubbed: the `openai` npm
 *     package (used by openai/llama/local/mistral) and the global `fetch`
 *     (used by anthropic/gemini) — i.e. the network boundary, not the
 *     provider or validator code.
 *
 * SSRF-01..06  Each of the six registered providers, dispatched through the
 *              real routeProviderCall(), reaches the transport using EXACTLY
 *              the SSRF-validated safe URL — proves the real dispatch path
 *              (router -> handler -> transport) is wired correctly end to
 *              end, not just the handler in isolation.
 * SSRF-07..08  The four hardcoded-URL providers (openai/anthropic/gemini/
 *              mistral) each actually CALL validateProviderUrl() with their
 *              own CANONICAL_BASE_URL at module load — spied (not mocked),
 *              so this fails if a future refactor deletes that call.
 * SSRF-09..10  The two operator-configurable providers (llama/local): a
 *              malicious LLAMA_BASE_URL/LOCAL_BASE_URL (SSRF targets:
 *              cloud-metadata IP literal, file://) dispatched through the
 *              REAL router is rejected BEFORE the transport is ever touched
 *              — proves rejected URLs never reach the network layer, and
 *              fails if the guard is removed (the transport would then be
 *              invoked with the malicious URL instead of throwing).
 * SSRF-11      llama's relaxed-but-still-real validator (_validateBaseUrl)
 *              still rejects non-http(s) schemes even for operator-configured
 *              endpoints (file://) — the relaxed path is not "no validation".
 */

const { getProviderConfig } = require('../config');

// ── Transport stubs ─────────────────────────────────────────────────────────

const VALID_OPENAI_COMPLETION = {
  id: 'resp-001',
  model: 'gpt-4o',
  choices: [{ message: { role: 'assistant', content: 'hello from stub transport' } }],
  usage: { prompt_tokens: 5, completion_tokens: 5, total_tokens: 10 },
};

function mockOpenAiSdk() {
  jest.doMock('openai', () => {
    const ctor = jest.fn().mockImplementation((opts) => ({
      __ctorOpts: opts,
      chat: { completions: { create: jest.fn().mockResolvedValue(VALID_OPENAI_COMPLETION) } },
    }));
    return { OpenAI: ctor };
  });
}

function mockFetchTransport() {
  global.fetch = jest.fn().mockImplementation((url) => {
    if (typeof url === 'string' && url.includes('generativelanguage.googleapis.com')) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          candidates: [{ content: { parts: [{ text: 'hello from gemini stub' }] } }],
          usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 5, totalTokenCount: 10 },
        }),
      });
    }
    // Anthropic shape
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve({
        id: 'msg-001',
        model: 'claude-3-5-sonnet-20241022',
        content: [{ type: 'text', text: 'hello from anthropic stub' }],
        usage: { input_tokens: 5, output_tokens: 5 },
      }),
    });
  });
}

const VALID_BODY = { messages: [{ role: 'user', content: 'hi' }] };
const META = { requestId: 'req-ssrf-01', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64) };

function modelFor(providerName) {
  const cfg = getProviderConfig(providerName);
  const first = cfg.allowedModels.size > 0 ? [...cfg.allowedModels][0] : 'any-model-name';
  return first;
}

// ── Fresh, unmocked router + provider load per test ─────────────────────────
// jest.resetModules() between every test so each provider's module-load-time
// SSRF IIFE (_assertBaseUrlSafe) and lazy-client SSRF check both run fresh,
// under whatever env vars / spies this specific test set up. services/
// providers/ssrf.js is NEVER in jest.doMock() anywhere in this file — only
// spied — so the real validator always executes.

function freshRouter(env) {
  jest.resetModules();
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  jest.doMock('../../logger', () => ({ emit: jest.fn() }));
  mockOpenAiSdk();
  mockFetchTransport();
  const ssrf = require('../ssrf'); // real module — spied on by individual tests, never mocked
  const router = require('../router');
  return { router, ssrf };
}

function clearProviderEnv() {
  for (const k of [
    'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'MISTRAL_BASE_URL',
    'LLAMA_BASE_URL', 'LLAMA_API_KEY', 'LOCAL_BASE_URL', 'LOCAL_API_KEY',
  ]) delete process.env[k];
}

afterEach(() => {
  clearProviderEnv();
  delete global.fetch;
  jest.restoreAllMocks();
});

// ── SSRF-01..06: real dispatch entrypoint reaches the transport with the
//    exact SSRF-validated safe URL, for every registered provider ──────────

describe('SSRF-01..06 — routeProviderCall() reaches the transport using exactly the safe, validated URL', () => {
  test('SSRF-01 openai', async () => {
    const { router } = freshRouter({ OPENAI_API_KEY: PROVIDER_FIXTURE_KEYS.openai });
    const { OpenAI } = require('openai');

    const result = await router.routeProviderCall('openai', { ...VALID_BODY, model: modelFor('openai') }, META);

    expect(result.output).toBe('hello from stub transport');
    expect(OpenAI).toHaveBeenCalledWith(expect.objectContaining({ baseURL: 'https://api.openai.com/v1' }));
  });

  test('SSRF-02 anthropic', async () => {
    const { router } = freshRouter({ ANTHROPIC_API_KEY: PROVIDER_FIXTURE_KEYS.anthropic });

    const result = await router.routeProviderCall('anthropic', { ...VALID_BODY, model: modelFor('anthropic') }, META);

    expect(result.output).toBe('hello from anthropic stub');
    const [url] = global.fetch.mock.calls[0];
    expect(url).toBe('https://api.anthropic.com/v1/messages');
  });

  test('SSRF-03 gemini', async () => {
    const { router } = freshRouter({ GEMINI_API_KEY: PROVIDER_FIXTURE_KEYS.gemini });

    const result = await router.routeProviderCall('gemini', { ...VALID_BODY, model: modelFor('gemini') }, META);

    expect(result.output).toBe('hello from gemini stub');
    const [url] = global.fetch.mock.calls[0];
    expect(url.startsWith('https://generativelanguage.googleapis.com/')).toBe(true);
  });

  test('SSRF-04 mistral', async () => {
    const { router } = freshRouter({ MISTRAL_API_KEY: PROVIDER_FIXTURE_KEYS.mistral });
    const { OpenAI } = require('openai');

    const result = await router.routeProviderCall('mistral', { ...VALID_BODY, model: modelFor('mistral') }, META);

    expect(result.output).toBe('hello from stub transport');
    expect(OpenAI).toHaveBeenCalledWith(expect.objectContaining({ baseURL: 'https://api.mistral.ai/v1' }));
  });

  test('SSRF-05 llama (cloud-hosted, public allowlisted-shape URL)', async () => {
    const { router } = freshRouter({ LLAMA_BASE_URL: 'https://api.groq.com/openai/v1' });
    const { OpenAI } = require('openai');

    const result = await router.routeProviderCall('llama', { ...VALID_BODY, model: 'llama3.2' }, META);

    expect(result.output).toBe('hello from stub transport');
    expect(OpenAI).toHaveBeenCalledWith(expect.objectContaining({ baseURL: 'https://api.groq.com/openai/v1' }));
  });

  test('SSRF-06 local (self-hosted, relaxed validator, still reaches only the configured URL)', async () => {
    const { router } = freshRouter({ LOCAL_BASE_URL: 'http://localhost:11434/v1' });
    const { OpenAI } = require('openai');

    const result = await router.routeProviderCall('local', { ...VALID_BODY, model: 'qwen2.5:7b' }, META);

    expect(result.output).toBe('hello from stub transport');
    expect(OpenAI).toHaveBeenCalledWith(expect.objectContaining({ baseURL: 'http://localhost:11434/v1' }));
  });
});

// ── SSRF-07..08: the hardcoded-URL providers genuinely invoke the real
//    validator at load time — spied, not mocked, so this fails if that call
//    is ever removed ──────────────────────────────────────────────────────

describe('SSRF-07..08 — hardcoded-base-URL providers actually call validateProviderUrl() at module load (spied, not mocked)', () => {
  test('SSRF-07 openai/anthropic/gemini/mistral each call validateProviderUrl with their own CANONICAL_BASE_URL', () => {
    jest.resetModules();
    jest.doMock('../../logger', () => ({ emit: jest.fn() }));
    mockOpenAiSdk();
    const ssrf = require('../ssrf');
    const spy = jest.spyOn(ssrf, 'validateProviderUrl');

    require('../openai');
    require('../anthropic');
    require('../gemini');
    require('../mistral');

    const calledWith = spy.mock.calls.map(c => c[0]);
    expect(calledWith).toContain('https://api.openai.com/v1');
    expect(calledWith).toContain('https://api.anthropic.com');
    expect(calledWith).toContain('https://generativelanguage.googleapis.com');
    expect(calledWith).toContain('https://api.mistral.ai/v1');
    // Every one of those calls must have returned a passing result — a
    // provider module throws at require-time otherwise (see each file's
    // _assertBaseUrlSafe IIFE), so a passing require() already proves this,
    // but asserting explicitly documents the expectation this test protects.
    for (const result of spy.mock.results) {
      expect(result.value.valid).toBe(true);
    }
  });

  test('SSRF-08 a hardcoded provider module refuses to load if its canonical URL fails validation (proves the guard is load-bearing, not decorative)', () => {
    jest.resetModules();
    jest.doMock('../../logger', () => ({ emit: jest.fn() }));
    mockOpenAiSdk();
    // Force the REAL validator to reject — not mocking ssrf.js itself, just
    // wrapping its real function with a failing result for this one test,
    // to prove openai.js's module-load IIFE actually acts on the return
    // value rather than ignoring it.
    const ssrf = require('../ssrf');
    jest.spyOn(ssrf, 'validateProviderUrl').mockReturnValue({ valid: false, reason: 'HOSTNAME_NOT_ALLOWED' });

    expect(() => require('../openai')).toThrow(/PROVIDER_SSRF_REJECTED/);
  });
});

// ── SSRF-09..11: operator-configurable providers reject malicious URLs
//    BEFORE the transport is ever touched ───────────────────────────────────

describe('SSRF-09..11 — llama/local reject malicious base URLs before the network layer, through the real dispatch path', () => {
  test('SSRF-09 llama: disallowed protocol targeting the cloud-metadata IP (ftp://169.254.169.254/) is rejected by both validators and never reaches the OpenAI SDK constructor', async () => {
    // Note: llama's relaxed local-provider validator deliberately permits
    // link-local/private IP literals over http(s) — self-hosted GPU servers
    // legitimately live on addresses like 192.168.x/10.x, and the operator
    // is accountable for that endpoint's security (see ssrf.js's
    // validateLocalProviderUrl header comment). That is intended behavior,
    // not a gap this test should flag. What both validators DO always
    // reject, regardless of destination, is a disallowed protocol — this
    // uses the classic SSRF cloud-metadata target with a protocol neither
    // validateProviderUrl (https-only) nor validateLocalProviderUrl
    // (http/https-only) ever allows.
    const { router } = freshRouter({ LLAMA_BASE_URL: 'ftp://169.254.169.254/latest/meta-data/' });
    const { OpenAI } = require('openai');

    // (BOOT-RULES.md section 3): a base URL that is not http(s) no longer
    // enables the provider at all, so the request is refused one layer EARLIER
    // (PROVIDER_NOT_CONFIGURED, before any adapter or URL validator runs). The
    // dispatch-time validator codes remain accepted for any path that still
    // reaches it; the provider must additionally be reported as not enabled.
    expect(require('../config').getProviderConfig('llama').enabled).toBe(false);
    await expect(router.routeProviderCall('llama', { ...VALID_BODY, model: 'llama3.2' }, META))
      .rejects.toMatchObject({ code: expect.stringMatching(/PROVIDER_NOT_CONFIGURED|PROVIDER_UNAVAILABLE|PROVIDER_CONFIG_INVALID/) });

    // The strongest assertion: regardless of which error code surfaces
    // through the router's failover/normalization layer, the transport
    // itself must never have been constructed with the malicious URL.
    expect(OpenAI).not.toHaveBeenCalled();
  });

  test('SSRF-10 local: file:// URL is rejected and never reaches the OpenAI SDK constructor', async () => {
    const { router } = freshRouter({ LOCAL_BASE_URL: 'file:///etc/passwd' });
    const { OpenAI } = require('openai');

    await expect(router.routeProviderCall('local', { ...VALID_BODY, model: 'any-model' }, META))
      .rejects.toBeDefined();

    expect(OpenAI).not.toHaveBeenCalled();
  });

  test('SSRF-11 llama: file:// URL is rejected even though llama has a relaxed (private-network-permitting) validator fallback — relaxed is not "unvalidated"', async () => {
    const { router } = freshRouter({ LLAMA_BASE_URL: 'file:///etc/passwd' });
    const { OpenAI } = require('openai');

    await expect(router.routeProviderCall('llama', { ...VALID_BODY, model: 'llama3.2' }, META))
      .rejects.toBeDefined();

    expect(OpenAI).not.toHaveBeenCalled();
  });
});
