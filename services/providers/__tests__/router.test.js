'use strict';

// the code under test reads the monotonic clock (src/infra/time/monotonicClock.js), which jest fake timers
// and Date.now spies do not move. Point it at Date.now so this suite keeps driving time the way it always has; the
// monotonic behaviour itself is pinned by src/infra/time/__tests__/monotonicSites.test.js.
jest.mock('../../../src/infra/time/monotonicClock', () => ({ monoNowMs: () => Date.now(), wallFromMono: (m) => m || null }));

jest.mock('../../logger', () => ({ emit: jest.fn() }));

// Mock all individual provider handlers
jest.mock('../openai',    () => ({ callOpenAI:    jest.fn() }));
jest.mock('../anthropic', () => ({ callAnthropic: jest.fn() }));
jest.mock('../gemini',    () => ({ callGemini:    jest.fn() }));
jest.mock('../mistral',   () => ({ callMistral:   jest.fn() }));
jest.mock('../llama',     () => ({ callLlama:     jest.fn() }));
jest.mock('../local',     () => ({ callLocal:     jest.fn() }));

// Mock config module to control which providers are enabled
jest.mock('../config', () => ({
  getProviderConfig: jest.fn(),
}));

const { emit }                = require('../../logger');
const { getProviderConfig }   = require('../config');
const { callOpenAI }          = require('../openai');
const { callAnthropic }       = require('../anthropic');
const { callGemini }          = require('../gemini');
const { callMistral }         = require('../mistral');
const { callLlama }           = require('../llama');
const { callLocal }           = require('../local');
const { resetAll: resetProviderCircuitBreakers } = require('../providerCircuitBreaker');
const { resetAll: resetProviderHealth } = require('../providerHealth');

// Load router after mocks are set up
const { routeProviderCall, listProviders, listEnabledProviders } = require('../router');

// ── Helpers ───────────────────────────────────────────────────────────────────

const VALID_BODY = {
  model:    'gpt-4o',
  messages: [{ role: 'user', content: 'Hello' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
  // failover needs the caller's authorization; these tests cover the
  // routing mechanics for a caller whose failover IS authorized. The rules
  // themselves are pinned in 'failover authorization' below.
  authorizeFailover: async () => ({ ok: true }),
};

const MOCK_RESPONSE = Object.freeze({
  output:   'Hello!',
  model:    'gpt-4o',
  provider: 'openai',
  tokenUsage: { inputTokens: 5, outputTokens: 10, totalTokens: 15 },
  executionMetadata: { responseId: 'resp-001', latencyMs: 50 },
});

// the router now validates `body.model` against `config.allowedModels`
// before dispatching. An empty Set means "unrestricted" (see config.js /
// modelValidation.js), which keeps every pre-existing test below — none of
// which are about the allowlist — passing unchanged regardless of which
// model name they use.
function enabledConfig(failover = null) {
  return { enabled: true, failoverProvider: failover, allowedModels: new Set() };
}

function disabledConfig() {
  return { enabled: false, failoverProvider: null, allowedModels: new Set() };
}

beforeEach(() => {
  jest.clearAllMocks();
  // Every provider's circuit breaker starts CLOSED for each test — the
  // breaker registry is a module-level singleton and several tests below
  // deliberately force provider failures (Register #107).
  resetProviderCircuitBreakers();
  resetProviderHealth();
});

// ── Provider selection ────────────────────────────────────────────────────────

describe('provider selection', () => {
  test('routes to openai when provider=openai', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);
    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);
    // Third argument is the (here, absent) cancellation AbortSignal — see
    // Finding 32 remediation: routeProviderCall/_dispatch always forwards it
    // to the handler, so a call with no signal still passes explicit
    // `undefined` as the third argument.
    expect(callOpenAI).toHaveBeenCalledWith(VALID_BODY, VALID_META, undefined);
    expect(result).toBe(MOCK_RESPONSE);
  });

  test('routes to anthropic when provider=anthropic', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('anthropic', { ...VALID_BODY, model: 'claude-3-5-sonnet-20241022' }, VALID_META);
    expect(callAnthropic).toHaveBeenCalled();
  });

  test('routes to gemini when provider=gemini', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callGemini.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('gemini', { ...VALID_BODY, model: 'gemini-1.5-flash' }, VALID_META);
    expect(callGemini).toHaveBeenCalled();
  });

  test('routes to mistral when provider=mistral', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callMistral.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('mistral', { ...VALID_BODY, model: 'mistral-large-latest' }, VALID_META);
    expect(callMistral).toHaveBeenCalled();
  });

  test('routes to llama when provider=llama', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callLlama.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('llama', { ...VALID_BODY, model: 'llama3.2' }, VALID_META);
    expect(callLlama).toHaveBeenCalled();
  });

  test('routes to local when provider=local', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callLocal.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('local', { ...VALID_BODY, model: 'llama3.2' }, VALID_META);
    expect(callLocal).toHaveBeenCalled();
  });

  test('only the selected provider is called', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(callAnthropic).not.toHaveBeenCalled();
    expect(callGemini).not.toHaveBeenCalled();
    expect(callMistral).not.toHaveBeenCalled();
    expect(callLlama).not.toHaveBeenCalled();
    expect(callLocal).not.toHaveBeenCalled();
  });
});

// ── Routing decisions logged ──────────────────────────────────────────────────

describe('routing decisions are logged', () => {
  test('emits PROVIDER_ROUTING_DECISION', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_ROUTING_DECISION', expect.objectContaining({
      requestedProvider: 'openai',
      selectedProvider:  'openai',
      requestId:         'req-001',
    }));
  });
});

// ── Provider not registered ───────────────────────────────────────────────────

describe('unknown provider', () => {
  test('throws PROVIDER_UNAVAILABLE for unknown provider name', async () => {
    getProviderConfig.mockReturnValue(null);
    const err = await routeProviderCall('unknown-ai', VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('throws PROVIDER_UNAVAILABLE for null provider', async () => {
    const err = await routeProviderCall(null, VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('throws PROVIDER_UNAVAILABLE for empty string provider', async () => {
    const err = await routeProviderCall('', VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });
});

// ── Provider not configured ───────────────────────────────────────────────────

describe('provider not configured', () => {
  test('throws PROVIDER_NOT_CONFIGURED when provider disabled', async () => {
    getProviderConfig.mockReturnValue(disabledConfig());
    const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_NOT_CONFIGURED');
    expect(callOpenAI).not.toHaveBeenCalled();
  });

  test('emits PROVIDER_NOT_CONFIGURED warning', async () => {
    getProviderConfig.mockReturnValue(disabledConfig());
    await routeProviderCall('openai', VALID_BODY, VALID_META).catch(() => {});
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_NOT_CONFIGURED', expect.any(Object));
  });
});

// ── Failover behavior ─────────────────────────────────────────────────────────

describe('failover behavior', () => {
  test('tries failover provider on PROVIDER_UNAVAILABLE', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    const unavailableErr = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(unavailableErr);
    callAnthropic.mockResolvedValue({ ...MOCK_RESPONSE, provider: 'anthropic' });

    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(callOpenAI).toHaveBeenCalled();
    expect(callAnthropic).toHaveBeenCalled();
    expect(result.provider).toBe('anthropic');
  });

  test('tries failover on PROVIDER_RATE_LIMITED', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    const rateLimitErr = Object.assign(new Error('rate limited'), { code: 'PROVIDER_RATE_LIMITED' });
    callOpenAI.mockRejectedValue(rateLimitErr);
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);

    await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(callAnthropic).toHaveBeenCalled();
  });

  test('tries failover on PROVIDER_TIMEOUT', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    const timeoutErr = Object.assign(new Error('timeout'), { code: 'PROVIDER_TIMEOUT' });
    callOpenAI.mockRejectedValue(timeoutErr);
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);

    await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(callAnthropic).toHaveBeenCalled();
  });

  // a completion the first provider may already have run is never sent to a second provider.
  test.each(['PROVIDER_UNAVAILABLE', 'PROVIDER_TIMEOUT'])('does NOT failover on %s when the provider may have executed', async (code) => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    callOpenAI.mockRejectedValue(Object.assign(new Error(code), { code, providerMayHaveExecuted: true }));
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);

    await expect(routeProviderCall('openai', VALID_BODY, VALID_META)).rejects.toMatchObject({ code });
    expect(callAnthropic).not.toHaveBeenCalled();
  });

  test('does NOT failover on PROVIDER_AUTH_FAILED (non-retryable)', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai') return enabledConfig('anthropic');
      return null;
    });
    const authErr = Object.assign(new Error('auth'), { code: 'PROVIDER_AUTH_FAILED' });
    callOpenAI.mockRejectedValue(authErr);

    const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
    expect(callAnthropic).not.toHaveBeenCalled();
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('does NOT failover on PROVIDER_MODEL_NOT_ALLOWED (non-retryable)', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai') return enabledConfig('anthropic');
      return null;
    });
    const modelErr = Object.assign(new Error('model'), { code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    callOpenAI.mockRejectedValue(modelErr);

    await routeProviderCall('openai', VALID_BODY, VALID_META).catch(() => {});
    expect(callAnthropic).not.toHaveBeenCalled();
  });

  test('does not failover when no failover provider configured', async () => {
    getProviderConfig.mockReturnValue(enabledConfig(null));
    const unavailableErr = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(unavailableErr);

    const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
    expect(callAnthropic).not.toHaveBeenCalled();
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('emits PROVIDER_FAILOVER when switching providers', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    const unavailableErr = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(unavailableErr);
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);

    await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_FAILOVER', expect.objectContaining({
      primaryProvider:  'openai',
      failoverProvider: 'anthropic',
    }));
  });

  test('emits PROVIDER_FAILOVER_SUCCESS on successful failover', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    const unavailableErr = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(unavailableErr);
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);

    await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_FAILOVER_SUCCESS', expect.any(Object));
  });

  test('emits PROVIDER_FAILOVER_FAILED when failover also fails', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    const err1 = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    const err2 = Object.assign(new Error('also unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(err1);
    callAnthropic.mockRejectedValue(err2);

    await routeProviderCall('openai', VALID_BODY, VALID_META).catch(() => {});
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_FAILOVER_FAILED', expect.any(Object));
  });

  test('throws failover error when both providers fail', async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    const err1 = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    const err2 = Object.assign(new Error('also unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(err1);
    callAnthropic.mockRejectedValue(err2);

    const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('prevents infinite failover chains', async () => {
    // openai → anthropic → but anthropic has a failover too (should not recurse further)
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig('openai');  // circular
      return null;
    });
    const err1 = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    const err2 = Object.assign(new Error('also unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(err1);
    callAnthropic.mockRejectedValue(err2);

    const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    // openai called once, anthropic called once — no infinite loop
    expect(callOpenAI).toHaveBeenCalledTimes(1);
    expect(callAnthropic).toHaveBeenCalledTimes(1);
  });
});

// ── Model allowlist — validated before provider selection ───────────────

describe('model allowlist enforcement', () => {
  test('rejects a model outside the provider allowlist before dispatching', async () => {
    getProviderConfig.mockReturnValue({ enabled: true, failoverProvider: null, allowedModels: new Set(['gpt-4o']) });
    const err = await routeProviderCall('openai', { ...VALID_BODY, model: 'gpt-999-ultra' }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    expect(callOpenAI).not.toHaveBeenCalled();
  });

  test('allows a model inside the provider allowlist', async () => {
    getProviderConfig.mockReturnValue({ enabled: true, failoverProvider: null, allowedModels: new Set(['gpt-4o']) });
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(callOpenAI).toHaveBeenCalled();
  });

  test('empty allowlist (deployment-specific provider) accepts any well-formed model', async () => {
    getProviderConfig.mockReturnValue({ enabled: true, failoverProvider: null, allowedModels: new Set() });
    callLlama.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('llama', { ...VALID_BODY, model: 'custom-deployment-model' }, VALID_META);
    expect(callLlama).toHaveBeenCalled();
  });

  test('rejects an oversized model string before dispatching, even under an empty (unrestricted) allowlist', async () => {
    getProviderConfig.mockReturnValue({ enabled: true, failoverProvider: null, allowedModels: new Set() });
    const err = await routeProviderCall('llama', { ...VALID_BODY, model: 'x'.repeat(200) }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    expect(callLlama).not.toHaveBeenCalled();
  });

  test('rejects null, empty, and whitespace-only models', async () => {
    getProviderConfig.mockReturnValue({ enabled: true, failoverProvider: null, allowedModels: new Set(['gpt-4o']) });
    for (const model of [null, '', '   ', undefined]) {
      const err = await routeProviderCall('openai', { ...VALID_BODY, model }, VALID_META).catch(e => e);
      expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    }
    expect(callOpenAI).not.toHaveBeenCalled();
  });

  test('emits PROVIDER_MODEL_NOT_ALLOWED warning on rejection', async () => {
    getProviderConfig.mockReturnValue({ enabled: true, failoverProvider: null, allowedModels: new Set(['gpt-4o']) });
    await routeProviderCall('openai', { ...VALID_BODY, model: 'not-allowed' }, VALID_META).catch(() => {});
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_MODEL_NOT_ALLOWED', expect.any(Object));
  });

  test("re-validates the model against the failover target's own allowlist, not the primary's", async () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return { enabled: true, failoverProvider: 'anthropic', allowedModels: new Set(['gpt-4o']) };
      if (name === 'anthropic') return { enabled: true, failoverProvider: null, allowedModels: new Set(['claude-3-5-sonnet-20241022']) };
      return null;
    });
    const unavailableErr = Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' });
    callOpenAI.mockRejectedValue(unavailableErr);

    // 'gpt-4o' is valid for openai but is not in anthropic's allowlist —
    // the failover attempt must reject it rather than blindly forwarding it.
    const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
    expect(callAnthropic).not.toHaveBeenCalled();
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('does not consult config.js allowedModels for an unregistered provider (fails earlier, on registration)', async () => {
    getProviderConfig.mockReturnValue(null);
    const err = await routeProviderCall('unknown-ai', VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });
});

// ── Registry introspection ────────────────────────────────────────────────────

describe('listProviders', () => {
  test('returns all registered provider names', () => {
    const providers = listProviders();
    expect(providers).toContain('openai');
    expect(providers).toContain('anthropic');
    expect(providers).toContain('gemini');
    expect(providers).toContain('mistral');
    expect(providers).toContain('llama');
    expect(providers).toContain('local');
  });
});

describe('listEnabledProviders', () => {
  test('returns only providers whose config.enabled is true', () => {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai' || name === 'anthropic') return enabledConfig();
      return disabledConfig();
    });
    const enabled = listEnabledProviders();
    expect(enabled).toContain('openai');
    expect(enabled).toContain('anthropic');
    expect(enabled).not.toContain('gemini');
    expect(enabled).not.toContain('mistral');
    expect(enabled).not.toContain('llama');
    expect(enabled).not.toContain('local');
  });
});

// ── Audit — routing decisions always recorded ─────────────────────────────────

describe('audit validation', () => {
  test('routing decisions always include requestId for traceability', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);
    await routeProviderCall('openai', VALID_BODY, VALID_META);
    const routingCall = emit.mock.calls.find(([, code]) => code === 'PROVIDER_ROUTING_DECISION');
    expect(routingCall).toBeDefined();
    expect(routingCall[2].requestId).toBe('req-001');
  });
});

// ── Circuit breaker (Register #107) — fault injection ─────────────────────────

describe('circuit breaker', () => {
  test('fast-fails after the failure threshold without invoking the handler again', async () => {
    // No failover configured — isolates breaker behavior from failover logic.
    getProviderConfig.mockReturnValue(enabledConfig());
    const timeoutErr = Object.assign(new Error('timed out'), { code: 'PROVIDER_TIMEOUT' });
    callOpenAI.mockRejectedValue(timeoutErr);

    // Default threshold is 5 consecutive failures (PROVIDER_CB_FAILURE_THRESHOLD).
    for (let i = 0; i < 5; i++) {
      const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
      expect(err.code).toBe('PROVIDER_TIMEOUT');
    }
    expect(callOpenAI).toHaveBeenCalledTimes(5);

    // 6th call: breaker is OPEN — must fast-fail without calling the handler again.
    const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_CIRCUIT_OPEN');
    expect(callOpenAI).toHaveBeenCalledTimes(5);
  });

  test('an OPEN circuit still triggers failover to a configured target', async () => {
    // prime openai's breaker to OPEN with no failover configured
    // yet, so priming failures don't themselves succeed via failover.
    getProviderConfig.mockReturnValue(enabledConfig());
    const timeoutErr = Object.assign(new Error('timed out'), { code: 'PROVIDER_TIMEOUT' });
    callOpenAI.mockRejectedValue(timeoutErr);

    for (let i = 0; i < 5; i++) {
      await routeProviderCall('openai', VALID_BODY, VALID_META).catch(() => {});
    }
    expect(callOpenAI).toHaveBeenCalledTimes(5);

    // now configure a failover target and make the call. The
    // circuit is OPEN for openai — it should fast-fail on openai without
    // invoking the handler again, and still successfully fail over to
    // anthropic instead of surfacing the circuit-open error to the caller.
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai') return enabledConfig('anthropic');
      return enabledConfig();
    });
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);

    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(result).toBe(MOCK_RESPONSE);
    expect(callOpenAI).toHaveBeenCalledTimes(5); // not called a 6th time
    expect(callAnthropic).toHaveBeenCalledTimes(1);
  });

  test('a config/model-allowlist rejection never counts against the breaker', async () => {
    getProviderConfig.mockReturnValue({ enabled: true, failoverProvider: null, allowedModels: new Set(['only-this-model']) });

    for (let i = 0; i < 10; i++) {
      const err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
      expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    }
    expect(callOpenAI).not.toHaveBeenCalled();

    // Breaker never tripped — a subsequent call with an allowed model still
    // reaches the (successful) handler rather than fast-failing.
    getProviderConfig.mockReturnValue(enabledConfig());
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);
    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);
    expect(result).toBe(MOCK_RESPONSE);
  });

  test('recovers to CLOSED after the recovery window and a successful probe', async () => {
    jest.useFakeTimers({ doNotFake: ['nextTick', 'queueMicrotask'] });
    try {
      getProviderConfig.mockReturnValue(enabledConfig());
      const timeoutErr = Object.assign(new Error('timed out'), { code: 'PROVIDER_TIMEOUT' });
      callOpenAI.mockRejectedValue(timeoutErr);

      for (let i = 0; i < 5; i++) {
        await routeProviderCall('openai', VALID_BODY, VALID_META).catch(() => {});
      }
      // Breaker OPEN — immediate retry still fast-fails.
      let err = await routeProviderCall('openai', VALID_BODY, VALID_META).catch(e => e);
      expect(err.code).toBe('PROVIDER_CIRCUIT_OPEN');

      // Advance past the recovery window (default 30000ms) then succeed twice
      // (default success threshold is 2) to close the circuit.
      jest.advanceTimersByTime(30_001);
      callOpenAI.mockResolvedValue(MOCK_RESPONSE);

      const r1 = await routeProviderCall('openai', VALID_BODY, VALID_META);
      expect(r1).toBe(MOCK_RESPONSE);
      const r2 = await routeProviderCall('openai', VALID_BODY, VALID_META);
      expect(r2).toBe(MOCK_RESPONSE);

      // Fully closed again — an ordinary call succeeds without any special handling.
      const r3 = await routeProviderCall('openai', VALID_BODY, VALID_META);
      expect(r3).toBe(MOCK_RESPONSE);
    } finally {
      jest.useRealTimers();
    }
  });
});

// ── Health-aware routing (FAILOVER-4) ──────────────────────────────────────────

describe('health-aware routing', () => {
  const { recordOutcome, snapshot } = require('../providerHealth');
  const degradedOutcome = { ok: false, timedOut: true, latencyMs: 8_000 };

  test('a primary with a degraded health history (5+ samples, low score) is skipped entirely in favor of a healthy failover target', async () => {
    // Seed openai's health tracker directly with enough evidence to cross
    // the default degraded-score threshold — isolates the health-aware
    // pre-check from the circuit breaker (which independently trips at 5
    // consecutive failures too; seeding via recordOutcome() rather than
    // driving 5 real failing calls means the breaker itself never sees a
    // failure and stays CLOSED, proving this is the health check, not the
    // breaker, causing the skip).
    for (let i = 0; i < 5; i++) recordOutcome('openai', degradedOutcome);
    expect(snapshot('openai').score).toBeLessThan(0.5);

    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai') return enabledConfig('anthropic');
      return enabledConfig();
    });
    callAnthropic.mockResolvedValue(MOCK_RESPONSE);

    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);

    expect(result).toBe(MOCK_RESPONSE);
    expect(callOpenAI).not.toHaveBeenCalled(); // never even attempted
    expect(callAnthropic).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_HEALTH_DEGRADED_SKIP', expect.objectContaining({
      provider: 'openai',
      failoverTarget: 'anthropic',
    }));
  });

  test('does NOT skip when the failover target is equally/more degraded — still attempts the primary', async () => {
    for (let i = 0; i < 5; i++) {
      recordOutcome('openai', degradedOutcome);
      recordOutcome('anthropic', degradedOutcome);
    }

    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai') return enabledConfig('anthropic');
      return enabledConfig();
    });
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);

    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);

    expect(result).toBe(MOCK_RESPONSE);
    expect(callOpenAI).toHaveBeenCalledTimes(1); // primary WAS attempted
  });

  test('does NOT skip on fewer than the minimum sample count, even at 100% failure rate', async () => {
    recordOutcome('openai', degradedOutcome);
    recordOutcome('openai', degradedOutcome); // only 2 samples — below default minSamples (5)

    getProviderConfig.mockReturnValue(enabledConfig('anthropic'));
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);

    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);

    expect(result).toBe(MOCK_RESPONSE);
    expect(callOpenAI).toHaveBeenCalledTimes(1);
  });

  test('does NOT skip when no failover target is configured — there is nowhere to redirect to', async () => {
    for (let i = 0; i < 5; i++) recordOutcome('openai', degradedOutcome);

    getProviderConfig.mockReturnValue(enabledConfig(null)); // no failover configured
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);

    const result = await routeProviderCall('openai', VALID_BODY, VALID_META);

    expect(result).toBe(MOCK_RESPONSE);
    expect(callOpenAI).toHaveBeenCalledTimes(1);
  });

  test('a successful call is recorded into the provider health tracker', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);

    expect(snapshot('openai').samples).toBe(0);
    await routeProviderCall('openai', VALID_BODY, VALID_META);

    const s = snapshot('openai');
    expect(s.samples).toBe(1);
    expect(s.failureRate).toBe(0);
    expect(s.score).toBe(1);
  });

  test('a failed call is recorded into the provider health tracker with timedOut classification', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    const timeoutErr = Object.assign(new Error('timed out'), { code: 'PROVIDER_TIMEOUT' });
    callOpenAI.mockRejectedValue(timeoutErr);

    await routeProviderCall('openai', VALID_BODY, VALID_META).catch(() => {});

    const s = snapshot('openai');
    expect(s.samples).toBe(1);
    expect(s.failureRate).toBe(1);
    expect(s.timeoutRate).toBe(1);
  });
});


describe('failover authorization', () => {
  function primaryFails() {
    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai')    return enabledConfig('anthropic');
      if (name === 'anthropic') return enabledConfig(null);
      return null;
    });
    callOpenAI.mockRejectedValue(Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' }));
    callAnthropic.mockResolvedValue({ ...MOCK_RESPONSE, provider: 'anthropic' });
  }
  const bareMeta = { requestId: 'req-w6', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64) };

  test('FO-01 no authorizer supplied → no failover: the target is never called, the primary error is returned', async () => {
    primaryFails();
    const err = await routeProviderCall('openai', VALID_BODY, bareMeta).catch((e) => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    expect(callAnthropic).not.toHaveBeenCalled();
    expect(err.failoverRefused).toEqual({ target: 'anthropic', reason: 'FAILOVER_NOT_AUTHORIZED_NO_CHECK' });
  });

  test('FO-02 authorizer refuses (e.g. no consent for the target) → refused, target never called, reported', async () => {
    primaryFails();
    const routing = [];
    const authorizeFailover = jest.fn(async () => ({ ok: false, reason: 'CONSENT_REQUIRED' }));
    const err = await routeProviderCall('openai', VALID_BODY, { ...bareMeta, authorizeFailover, onRouting: (r) => routing.push(r) }).catch((e) => e);
    expect(authorizeFailover).toHaveBeenCalledWith('anthropic', { primary: 'openai', cause: 'PROVIDER_UNAVAILABLE', model: VALID_BODY.model });   // gate N-01: the model that will be sent
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    expect(callAnthropic).not.toHaveBeenCalled();
    expect(routing).toEqual([{ requestedProvider: 'openai', executingProvider: null, failover: { from: 'openai', to: 'anthropic', cause: 'PROVIDER_UNAVAILABLE', refused: 'CONSENT_REQUIRED' } }]);
  });

  test('FO-03 an authorizer that throws refuses (fail closed)', async () => {
    primaryFails();
    const err = await routeProviderCall('openai', VALID_BODY, { ...bareMeta, authorizeFailover: async () => { throw new Error('boom'); } }).catch((e) => e);
    expect(err.failoverRefused.reason).toBe('FAILOVER_AUTHORIZATION_ERROR');
    expect(callAnthropic).not.toHaveBeenCalled();
  });

  test('FO-04 authorized failover executes on the target and reports requested vs executing provider', async () => {
    primaryFails();
    const routing = [];
    const result = await routeProviderCall('openai', VALID_BODY, { ...bareMeta, authorizeFailover: async () => ({ ok: true }), onRouting: (r) => routing.push(r) });
    expect(result.provider).toBe('anthropic');
    expect(routing.pop()).toEqual({ requestedProvider: 'openai', executingProvider: 'anthropic', failover: { from: 'openai', to: 'anthropic', cause: 'PROVIDER_UNAVAILABLE' } });
  });

  test('FO-05 no failover: the executing provider is the requested one', async () => {
    getProviderConfig.mockImplementation(() => enabledConfig(null));
    callOpenAI.mockResolvedValue(MOCK_RESPONSE);
    const routing = [];
    await routeProviderCall('openai', VALID_BODY, { ...bareMeta, onRouting: (r) => routing.push(r) });
    expect(routing).toEqual([{ requestedProvider: 'openai', executingProvider: 'openai', failover: null }]);
  });
});
