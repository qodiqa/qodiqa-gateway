'use strict';

/**
 * Streaming router — dispatch registry coverage.
 *
 * Proves the actual fix at the dispatch layer: mistral and llama now
 * resolve to their own native streaming handlers via STREAMING_REGISTRY,
 * the same as openai/anthropic/local always have — NOT the _wrapNonStreaming()
 * single-chunk fallback they silently used before this item. gemini is
 * deliberately left on the fallback path — this suite also pins that gemini's
 * behavior is UNCHANGED, not regressed.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('../openai.stream',    () => ({ callOpenAIStream:    jest.fn() }));
jest.mock('../anthropic.stream', () => ({ callAnthropicStream: jest.fn() }));
jest.mock('../mistral.stream',   () => ({ callMistralStream:   jest.fn() }));
jest.mock('../llama.stream',     () => ({ callLlamaStream:     jest.fn() }));
jest.mock('../local.stream',     () => ({ callLocalStream:     jest.fn() }));
jest.mock('../config', () => ({ getProviderConfig: jest.fn() }));
jest.mock('../router', () => ({ routeProviderCall: jest.fn() }));

const { emit }              = require('../../logger');
const { getProviderConfig } = require('../config');
const { routeProviderCall } = require('../router');
const { callOpenAIStream }    = require('../openai.stream');
const { callAnthropicStream } = require('../anthropic.stream');
const { callMistralStream }   = require('../mistral.stream');
const { callLlamaStream }     = require('../llama.stream');
const { callLocalStream }     = require('../local.stream');

const { routeStreamingProviderCall } = require('../router.stream');

const VALID_BODY = { model: 'any-model', messages: [{ role: 'user', content: 'hi' }] };
const VALID_META = { requestId: 'req-001', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64) };

function enabledConfig() {
  return { enabled: true, failoverProvider: null, allowedModels: new Set() };
}

async function collect(gen) {
  const chunks = [];
  for await (const c of gen) chunks.push(c);
  return chunks;
}

beforeEach(() => {
  jest.clearAllMocks();
  getProviderConfig.mockImplementation(() => enabledConfig());
});

describe.each([
  ['mistral', () => callMistralStream],
  ['llama',   () => callLlamaStream],
])('%s now dispatches through its own native streaming handler', (provider, getHandler) => {
  test('routes to the native handler, not the non-streaming fallback', async () => {
    getHandler().mockImplementation(async function* () { yield { delta: `hi from ${provider}` }; });

    const chunks = await collect(routeStreamingProviderCall(provider, VALID_BODY, VALID_META));

    expect(chunks).toEqual([{ delta: `hi from ${provider}` }]);
    expect(getHandler()).toHaveBeenCalledTimes(1);
    expect(routeProviderCall).not.toHaveBeenCalled(); // _wrapNonStreaming's own call — must not fire
  });

  test('PROVIDER_STREAM_ROUTING_DECISION reports hasNativeStreaming: true', async () => {
    getHandler().mockImplementation(async function* () { yield { delta: 'x' }; });
    await collect(routeStreamingProviderCall(provider, VALID_BODY, VALID_META));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_ROUTING_DECISION', expect.objectContaining({
      requestedProvider:  provider,
      hasNativeStreaming: true,
    }));
  });

  test('a native handler error propagates without falling back to non-streaming', async () => {
    const err = new Error('PROVIDER_UNAVAILABLE'); err.code = 'PROVIDER_UNAVAILABLE';
    getHandler().mockImplementation(async function* () { throw err; });

    await expect(collect(routeStreamingProviderCall(provider, VALID_BODY, VALID_META)))
      .rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
    expect(routeProviderCall).not.toHaveBeenCalled();
  });
});

describe('gemini is unchanged — still uses the non-streaming fallback', () => {
  test('routes through _wrapNonStreaming(), not a native handler', async () => {
    routeProviderCall.mockResolvedValue({ output: 'hi from gemini (single chunk)' });

    const chunks = await collect(routeStreamingProviderCall('gemini', VALID_BODY, VALID_META));

    expect(chunks).toEqual([{ delta: 'hi from gemini (single chunk)' }]);
    expect(routeProviderCall).toHaveBeenCalledWith('gemini', VALID_BODY, expect.any(Object), undefined);
    expect(callOpenAIStream).not.toHaveBeenCalled();
    expect(callAnthropicStream).not.toHaveBeenCalled();
    expect(callMistralStream).not.toHaveBeenCalled();
    expect(callLlamaStream).not.toHaveBeenCalled();
    expect(callLocalStream).not.toHaveBeenCalled();
  });

  test('PROVIDER_STREAM_ROUTING_DECISION reports hasNativeStreaming: false for gemini', async () => {
    routeProviderCall.mockResolvedValue({ output: 'x' });
    await collect(routeStreamingProviderCall('gemini', VALID_BODY, VALID_META));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_ROUTING_DECISION', expect.objectContaining({
      requestedProvider:  'gemini',
      hasNativeStreaming: false,
    }));
  });

  test('an empty non-streaming response yields zero chunks (not an empty-string delta)', async () => {
    routeProviderCall.mockResolvedValue({ output: '' });
    const chunks = await collect(routeStreamingProviderCall('gemini', VALID_BODY, VALID_META));
    expect(chunks).toEqual([]);
  });
});

describe('openai/anthropic/local remain on their existing native handlers (no regression)', () => {
  test.each([
    ['openai',    () => callOpenAIStream],
    ['anthropic', () => callAnthropicStream],
    ['local',     () => callLocalStream],
  ])('%s still dispatches natively, unaffected by the mistral/llama registry additions', async (provider, getHandler) => {
    getHandler().mockImplementation(async function* () { yield { delta: `hi from ${provider}` }; });
    const chunks = await collect(routeStreamingProviderCall(provider, VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: `hi from ${provider}` }]);
    expect(routeProviderCall).not.toHaveBeenCalled();
  });
});
