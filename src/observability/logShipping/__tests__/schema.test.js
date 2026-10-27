'use strict';

const { normalizeEvent, _redact, _isSensitive } = require('../schema');

// ── _isSensitive ──────────────────────────────────────────────────────────────

describe('_isSensitive', () => {
  it('flags "authorization" as sensitive', () => {
    expect(_isSensitive('authorization')).toBe(true);
  });

  it('flags "apiKey" (camelCase) as sensitive', () => {
    expect(_isSensitive('apiKey')).toBe(true);
  });

  it('flags "api_key" (snake_case) as sensitive', () => {
    expect(_isSensitive('api_key')).toBe(true);
  });

  it('flags "password" as sensitive', () => {
    expect(_isSensitive('password')).toBe(true);
  });

  it('flags "secret" as sensitive', () => {
    expect(_isSensitive('secret')).toBe(true);
  });

  it('flags "token" as sensitive', () => {
    expect(_isSensitive('token')).toBe(true);
  });

  it('flags "privateKey" as sensitive', () => {
    expect(_isSensitive('privateKey')).toBe(true);
  });

  it('flags "signingKey" as sensitive', () => {
    expect(_isSensitive('signingKey')).toBe(true);
  });

  it('flags "bearer" as sensitive', () => {
    expect(_isSensitive('bearer')).toBe(true);
  });

  it('does not flag "message" as sensitive', () => {
    expect(_isSensitive('message')).toBe(false);
  });

  it('does not flag "requestId" as sensitive', () => {
    expect(_isSensitive('requestId')).toBe(false);
  });

  it('does not flag "tenantId" as sensitive', () => {
    expect(_isSensitive('tenantId')).toBe(false);
  });
});

// ── _redact ───────────────────────────────────────────────────────────────────

describe('_redact', () => {
  it('replaces sensitive top-level field with [REDACTED]', () => {
    const result = _redact({ token: 'super-secret', message: 'ok' }, 0);
    expect(result.token).toBe('[REDACTED]');
    expect(result.message).toBe('ok');
  });

  it('replaces sensitive nested field', () => {
    const obj = { headers: { authorization: 'Bearer xxx', accept: 'json' } };
    const result = _redact(obj, 0);
    expect(result.headers.authorization).toBe('[REDACTED]');
    expect(result.headers.accept).toBe('json');
  });

  it('handles arrays without corrupting them', () => {
    const obj = { items: ['a', 'b', 'c'] };
    const result = _redact(obj, 0);
    expect(result.items).toEqual(['a', 'b', 'c']);
  });

  it('does not mutate the input object', () => {
    const original = { token: 'secret', message: 'hi' };
    _redact(original, 0);
    expect(original.token).toBe('secret');
  });

  it('handles null values without throwing', () => {
    const obj = { apiKey: null, message: 'test' };
    const result = _redact(obj, 0);
    expect(result.apiKey).toBe('[REDACTED]');
  });

  it('handles primitive values as root (passthrough)', () => {
    expect(_redact('hello', 0)).toBe('hello');
    expect(_redact(42, 0)).toBe(42);
    expect(_redact(null, 0)).toBeNull();
  });
});

// ── normalizeEvent ────────────────────────────────────────────────────────────

describe('normalizeEvent', () => {
  const DEFAULTS = { service: 'qodiqa-test', environment: 'test' };

  it('sets all required schema fields', () => {
    const result = normalizeEvent({ event: 'TEST', level: 'INFO' }, DEFAULTS);
    expect(result).toHaveProperty('timestamp');
    expect(result).toHaveProperty('service', 'qodiqa-test');
    expect(result).toHaveProperty('environment', 'test');
    expect(result).toHaveProperty('tenantId');
    expect(result).toHaveProperty('tenantSlug');
    expect(result).toHaveProperty('eventType', 'TEST');
    expect(result).toHaveProperty('severity', 'INFO');
    expect(result).toHaveProperty('requestId');
    expect(result).toHaveProperty('traceId');
    expect(result).toHaveProperty('message');
    expect(result).toHaveProperty('metadata');
  });

  it('maps QODIQA logger "ts" field to "timestamp"', () => {
    const ts = '2026-01-01T00:00:00.000Z';
    const result = normalizeEvent({ ts, event: 'X', level: 'INFO' }, DEFAULTS);
    expect(result.timestamp).toBe(ts);
  });

  it('maps "event" to "eventType"', () => {
    const result = normalizeEvent({ event: 'CERT_STARTED', level: 'INFO' }, DEFAULTS);
    expect(result.eventType).toBe('CERT_STARTED');
  });

  it('maps "level" to "severity"', () => {
    const result = normalizeEvent({ event: 'X', level: 'WARN' }, DEFAULTS);
    expect(result.severity).toBe('WARN');
  });

  it('preserves tenantId and tenantSlug', () => {
    const result = normalizeEvent({
      event: 'X', level: 'INFO',
      tenantId: 'tid-001', tenantSlug: 'acme',
    }, DEFAULTS);
    expect(result.tenantId).toBe('tid-001');
    expect(result.tenantSlug).toBe('acme');
  });

  it('places unknown fields in metadata', () => {
    const result = normalizeEvent({
      event: 'X', level: 'INFO',
      certificationId: 'cert-001', score: 95,
    }, DEFAULTS);
    expect(result.metadata.certificationId).toBe('cert-001');
    expect(result.metadata.score).toBe(95);
  });

  it('redacts authorization header in metadata', () => {
    const result = normalizeEvent({
      event: 'X', level: 'INFO',
      headers: { authorization: 'Bearer abc123', 'content-type': 'application/json' },
    }, DEFAULTS);
    expect(result.metadata.headers.authorization).toBe('[REDACTED]');
    expect(result.metadata.headers['content-type']).toBe('application/json');
  });

  it('redacts apiKey in metadata', () => {
    const result = normalizeEvent({
      event: 'X', level: 'INFO',
      apiKey: 'my-key-123',
    }, DEFAULTS);
    expect(result.metadata.apiKey).toBe('[REDACTED]');
  });

  it('redacts password in metadata', () => {
    const result = normalizeEvent({
      event: 'X', level: 'INFO',
      password: 'hunter2',
    }, DEFAULTS);
    expect(result.metadata.password).toBe('[REDACTED]');
  });

  it('handles null/undefined raw event without throwing', () => {
    expect(() => normalizeEvent(null, DEFAULTS)).not.toThrow();
    expect(() => normalizeEvent(undefined, DEFAULTS)).not.toThrow();
  });

  it('uses defaults when raw event omits service/environment', () => {
    const result = normalizeEvent({}, DEFAULTS);
    expect(result.service).toBe('qodiqa-test');
    expect(result.environment).toBe('test');
  });

  it('generates a timestamp when none provided', () => {
    const before = new Date();
    const result = normalizeEvent({ event: 'X' }, DEFAULTS);
    const after  = new Date();
    const ts     = new Date(result.timestamp);
    expect(ts.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(ts.getTime()).toBeLessThanOrEqual(after.getTime());
  });
});
