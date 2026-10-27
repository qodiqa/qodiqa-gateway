'use strict';

const { buildResponse } = require('../normalize');

describe('buildResponse', () => {
  const BASE = {
    output:   'Hello, world!',
    model:    'test-model',
    provider: 'test-provider',
    tokenUsage: { inputTokens: 10, outputTokens: 20, totalTokens: 30 },
    executionMetadata: { responseId: 'resp-001', latencyMs: 123 },
  };

  test('builds a valid ProviderResponse', () => {
    const r = buildResponse(BASE);
    expect(r.output).toBe('Hello, world!');
    expect(r.model).toBe('test-model');
    expect(r.provider).toBe('test-provider');
    expect(r.tokenUsage.inputTokens).toBe(10);
    expect(r.tokenUsage.outputTokens).toBe(20);
    expect(r.tokenUsage.totalTokens).toBe(30);
    expect(r.executionMetadata.responseId).toBe('resp-001');
    expect(r.executionMetadata.latencyMs).toBe(123);
  });

  test('result is frozen at top level', () => {
    const r = buildResponse(BASE);
    expect(Object.isFrozen(r)).toBe(true);
  });

  test('tokenUsage is frozen', () => {
    const r = buildResponse(BASE);
    expect(Object.isFrozen(r.tokenUsage)).toBe(true);
  });

  test('executionMetadata is frozen', () => {
    const r = buildResponse(BASE);
    expect(Object.isFrozen(r.executionMetadata)).toBe(true);
  });

  test('throws PROVIDER_INVALID_RESPONSE when output is missing', () => {
    expect(() => buildResponse({ ...BASE, output: undefined }))
      .toThrow('PROVIDER_INVALID_RESPONSE');
  });

  test('throws PROVIDER_INVALID_RESPONSE when output is null', () => {
    expect(() => buildResponse({ ...BASE, output: null }))
      .toThrow('PROVIDER_INVALID_RESPONSE');
  });

  test('throws PROVIDER_INVALID_RESPONSE when output is number', () => {
    expect(() => buildResponse({ ...BASE, output: 42 }))
      .toThrow('PROVIDER_INVALID_RESPONSE');
  });

  test('throws PROVIDER_INVALID_RESPONSE when fields is null', () => {
    expect(() => buildResponse(null)).toThrow('PROVIDER_INVALID_RESPONSE');
  });

  test('model defaults to null when missing', () => {
    const r = buildResponse({ output: 'Hi' });
    expect(r.model).toBeNull();
  });

  test('provider defaults to null when missing', () => {
    const r = buildResponse({ output: 'Hi' });
    expect(r.provider).toBeNull();
  });

  test('tokenUsage fields default to null when missing', () => {
    const r = buildResponse({ output: 'Hi' });
    expect(r.tokenUsage.inputTokens).toBeNull();
    expect(r.tokenUsage.outputTokens).toBeNull();
    expect(r.tokenUsage.totalTokens).toBeNull();
  });

  test('executionMetadata defaults when missing', () => {
    const r = buildResponse({ output: 'Hi' });
    expect(r.executionMetadata.responseId).toBeNull();
    expect(r.executionMetadata.latencyMs).toBe(0);
  });

  test('accepts empty string output', () => {
    const r = buildResponse({ output: '' });
    expect(r.output).toBe('');
  });

  test('token values are rounded to integers', () => {
    const r = buildResponse({ output: 'Hi', tokenUsage: { inputTokens: 10.7, outputTokens: 20.3 } });
    expect(r.tokenUsage.inputTokens).toBe(11);
    expect(r.tokenUsage.outputTokens).toBe(20);
  });

  test('negative token values normalize to null', () => {
    const r = buildResponse({ output: 'Hi', tokenUsage: { inputTokens: -1 } });
    expect(r.tokenUsage.inputTokens).toBeNull();
  });

  test('NaN token values normalize to null', () => {
    const r = buildResponse({ output: 'Hi', tokenUsage: { inputTokens: NaN } });
    expect(r.tokenUsage.inputTokens).toBeNull();
  });

  test('error has .code property set', () => {
    try {
      buildResponse({ output: 42 });
    } catch (err) {
      expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
    }
  });
});
