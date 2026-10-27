'use strict';

const { mapToEcs, ECS_VERSION, SEVERITY_MAP, OUTCOME_MAP, CATEGORY_MAP } = require('../ecsMapper');

function normalizedEvent(overrides = {}) {
  return {
    timestamp:   '2026-01-01T00:00:00.000Z',
    service:     'qodiqa',
    environment: 'production',
    tenantId:    'tenant-1',
    tenantSlug:  'acme',
    eventType:   'AUDIT_CHAIN_CORRUPTED',
    severity:    'CRITICAL',
    requestId:   'req-1',
    traceId:     'trace-1',
    message:     'chain hash mismatch',
    metadata:    { category: 'SECURITY' },
    ...overrides,
  };
}

describe('mapToEcs', () => {
  test('maps timestamp, ecs.version, and service fields verbatim', () => {
    const ecs = mapToEcs(normalizedEvent());
    expect(ecs['@timestamp']).toBe('2026-01-01T00:00:00.000Z');
    expect(ecs.ecs.version).toBe(ECS_VERSION);
    expect(ecs.service).toEqual({ name: 'qodiqa', environment: 'production' });
  });

  test('event.action is the lowercased eventType', () => {
    const ecs = mapToEcs(normalizedEvent({ eventType: 'AUDIT_CHAIN_CORRUPTED' }));
    expect(ecs.event.action).toBe('audit_chain_corrupted');
  });

  test('qodiqa.event_type preserves the raw, unmodified eventType', () => {
    const ecs = mapToEcs(normalizedEvent({ eventType: 'AUDIT_CHAIN_CORRUPTED' }));
    expect(ecs.qodiqa.event_type).toBe('AUDIT_CHAIN_CORRUPTED');
  });

  test.each(Object.keys(SEVERITY_MAP))('event.severity for %s matches SEVERITY_MAP', (severity) => {
    const ecs = mapToEcs(normalizedEvent({ severity }));
    expect(ecs.event.severity).toBe(SEVERITY_MAP[severity]);
  });

  test('an unknown severity falls back to 3', () => {
    const ecs = mapToEcs(normalizedEvent({ severity: 'BOGUS' }));
    expect(ecs.event.severity).toBe(3);
  });

  test.each(Object.keys(OUTCOME_MAP))('event.outcome for %s matches OUTCOME_MAP', (severity) => {
    const ecs = mapToEcs(normalizedEvent({ severity }));
    expect(ecs.event.outcome).toBe(OUTCOME_MAP[severity]);
  });

  test.each(Object.keys(CATEGORY_MAP))('event.category for metadata.category=%s matches CATEGORY_MAP', (category) => {
    const ecs = mapToEcs(normalizedEvent({ metadata: { category } }));
    expect(ecs.event.category).toEqual(CATEGORY_MAP[category]);
  });

  test('an unrecognized metadata.category falls back to ["process"]', () => {
    const ecs = mapToEcs(normalizedEvent({ metadata: {} }));
    expect(ecs.event.category).toEqual(['process']);
  });

  test('trace.id is included when traceId is present', () => {
    const ecs = mapToEcs(normalizedEvent({ traceId: 'trace-42' }));
    expect(ecs.trace).toEqual({ id: 'trace-42' });
  });

  test('trace is omitted entirely when traceId is absent', () => {
    const ecs = mapToEcs(normalizedEvent({ traceId: null }));
    expect(ecs).not.toHaveProperty('trace');
  });

  test('qodiqa.tenant/request fields map from tenantId/tenantSlug/requestId', () => {
    const ecs = mapToEcs(normalizedEvent({ tenantId: 't1', tenantSlug: 'slug1', requestId: 'r1' }));
    expect(ecs.qodiqa.tenant).toEqual({ id: 't1', slug: 'slug1' });
    expect(ecs.qodiqa.request).toEqual({ id: 'r1' });
  });

  test('qodiqa.metadata carries through the full metadata object', () => {
    const ecs = mapToEcs(normalizedEvent({ metadata: { category: 'AUDIT', custom: 'x' } }));
    expect(ecs.qodiqa.metadata).toEqual({ category: 'AUDIT', custom: 'x' });
  });

  test('message maps verbatim', () => {
    const ecs = mapToEcs(normalizedEvent({ message: 'hello world' }));
    expect(ecs.message).toBe('hello world');
  });

  test('is deterministic — identical input produces identical output', () => {
    const event = normalizedEvent();
    expect(mapToEcs(event)).toEqual(mapToEcs(event));
  });

  test('never throws on a malformed/empty event', () => {
    expect(() => mapToEcs({})).not.toThrow();
    expect(() => mapToEcs(null)).not.toThrow();
    expect(() => mapToEcs(undefined)).not.toThrow();
  });
});
