'use strict';

/**
 * Streaming router — health-aware routing (FAILOVER-4).
 *
 * router.stream.js's native-streaming path (_guardedStream /
 * routeStreamingProviderCall) duplicates router.js's circuit-breaker and
 * failover mechanics for streaming call sites, since native stream handlers
 * bypass _dispatch() entirely — this suite covers that second integration
 * point for the FAILOVER-4 health-aware pre-check specifically, mirroring
 * router.test.js's "health-aware routing" suite for the non-streaming path.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('../openai.stream',    () => ({ callOpenAIStream:    jest.fn() }));
jest.mock('../anthropic.stream', () => ({ callAnthropicStream: jest.fn() }));
jest.mock('../local.stream',     () => ({ callLocalStream:     jest.fn() }));
jest.mock('../config', () => ({ getProviderConfig: jest.fn() }));

// router.stream.js's non-native-streaming fallback (_wrapNonStreaming) calls
// routeProviderCall() from router.js — mocked here since this suite is only
// about the native-streaming path's own health-aware check.
jest.mock('../router', () => ({ routeProviderCall: jest.fn() }));

const { emit }               = require('../../logger');
const { getProviderConfig }  = require('../config');
const { callOpenAIStream }    = require('../openai.stream');
const { callAnthropicStream } = require('../anthropic.stream');
const { resetAll: resetProviderCircuitBreakers } = require('../providerCircuitBreaker');
const { resetAll: resetProviderHealth, recordOutcome, snapshot } = require('../providerHealth');

const { routeStreamingProviderCall } = require('../router.stream');

const VALID_BODY = { model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }] };
// failover needs the caller's authorization — these tests cover routing for an authorized caller.
const VALID_META = { requestId: 'req-001', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64), authorizeFailover: async () => ({ ok: true }) };

function enabledConfig(failover = null) {
  return { enabled: true, failoverProvider: failover, allowedModels: new Set() };
}

async function collect(gen) {
  const chunks = [];
  for await (const c of gen) chunks.push(c);
  return chunks;
}

beforeEach(() => {
  jest.clearAllMocks();
  resetProviderCircuitBreakers();
  resetProviderHealth();
});

describe('streaming router — health-aware routing (FAILOVER-4)', () => {
  const degradedOutcome = { ok: false, timedOut: true, latencyMs: 8_000 };

  test('a degraded native-streaming primary is skipped entirely in favor of a healthy failover target', async () => {
    for (let i = 0; i < 5; i++) recordOutcome('openai', degradedOutcome);
    expect(snapshot('openai').score).toBeLessThan(0.5);

    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai') return enabledConfig('anthropic');
      return enabledConfig();
    });
    callAnthropicStream.mockImplementation(async function* () { yield { delta: 'hi from anthropic' }; });

    const chunks = await collect(routeStreamingProviderCall('openai', VALID_BODY, VALID_META));

    expect(chunks).toEqual([{ delta: 'hi from anthropic' }]);
    expect(callOpenAIStream).not.toHaveBeenCalled();
    expect(callAnthropicStream).toHaveBeenCalledTimes(1);
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_HEALTH_DEGRADED_SKIP', expect.objectContaining({
      provider: 'openai',
      failoverTarget: 'anthropic',
    }));
  });

  test('does not skip when the failover target is equally degraded', async () => {
    for (let i = 0; i < 5; i++) {
      recordOutcome('openai', degradedOutcome);
      recordOutcome('anthropic', degradedOutcome);
    }

    getProviderConfig.mockImplementation((name) => {
      if (name === 'openai') return enabledConfig('anthropic');
      return enabledConfig();
    });
    callOpenAIStream.mockImplementation(async function* () { yield { delta: 'hi' }; });

    const chunks = await collect(routeStreamingProviderCall('openai', VALID_BODY, VALID_META));

    expect(chunks).toEqual([{ delta: 'hi' }]);
    expect(callOpenAIStream).toHaveBeenCalledTimes(1);
  });

  test('a successful native stream is recorded into the shared provider health tracker', async () => {
    getProviderConfig.mockReturnValue(enabledConfig());
    callOpenAIStream.mockImplementation(async function* () { yield { delta: 'hi' }; });

    expect(snapshot('openai').samples).toBe(0);
    await collect(routeStreamingProviderCall('openai', VALID_BODY, VALID_META));

    const s = snapshot('openai');
    expect(s.samples).toBe(1);
    expect(s.score).toBe(1);
  });
});
