'use strict';

const { mapToCim, SEVERITY_MAP, SEVERITY_ID_MAP } = require('../cimMapper');

function normalizedEvent(overrides = {}) {
  return {
    timestamp:   '2026-01-01T00:00:00.000Z',
    service:     'qodiqa',
    environment: 'production',
    tenantId:    'tenant-1',
    eventType:   'AUDIT_CHAIN_CORRUPTED',
    severity:    'CRITICAL',
    requestId:   'req-1',
    traceId:     'trace-1',
    message:     'chain hash mismatch',
    metadata:    {},
    ...overrides,
  };
}

describe('mapToCim', () => {
  test('_time is Unix epoch seconds derived from timestamp', () => {
    const cim = mapToCim(normalizedEvent({ timestamp: '2026-01-01T00:00:00.000Z' }));
    expect(cim._time).toBe(Math.floor(new Date('2026-01-01T00:00:00.000Z').getTime() / 1000));
  });

  test('signature preserves the raw, unmodified eventType', () => {
    const cim = mapToCim(normalizedEvent({ eventType: 'AUDIT_CHAIN_CORRUPTED' }));
    expect(cim.signature).toBe('AUDIT_CHAIN_CORRUPTED');
  });

  test.each(Object.keys(SEVERITY_MAP))('severity for %s matches SEVERITY_MAP', (severity) => {
    const cim = mapToCim(normalizedEvent({ severity }));
    expect(cim.severity).toBe(SEVERITY_MAP[severity]);
  });

  test.each(Object.keys(SEVERITY_ID_MAP))('severity_id for %s matches SEVERITY_ID_MAP', (severity) => {
    const cim = mapToCim(normalizedEvent({ severity }));
    expect(cim.severity_id).toBe(SEVERITY_ID_MAP[severity]);
  });

  test('an unknown severity falls back to "informational" / severity_id 1', () => {
    const cim = mapToCim(normalizedEvent({ severity: 'BOGUS' }));
    expect(cim.severity).toBe('informational');
    expect(cim.severity_id).toBe(1);
  });

  test('dest maps from service, with vendor_product/app constants', () => {
    const cim = mapToCim(normalizedEvent({ service: 'qodiqa-prod' }));
    expect(cim.dest).toBe('qodiqa-prod');
    expect(cim.vendor_product).toBe('QODIQA Platform');
    expect(cim.app).toBe('qodiqa');
  });

  test('tenant/request_id map from tenantId/requestId', () => {
    const cim = mapToCim(normalizedEvent({ tenantId: 't1', requestId: 'r1' }));
    expect(cim.tenant).toBe('t1');
    expect(cim.request_id).toBe('r1');
  });

  test('trace_id is included when traceId is present, omitted when absent', () => {
    expect(mapToCim(normalizedEvent({ traceId: 'trace-42' })).trace_id).toBe('trace-42');
    expect(mapToCim(normalizedEvent({ traceId: null }))).not.toHaveProperty('trace_id');
  });

  test('description maps from message, truncated to 500 characters', () => {
    const longMessage = 'x'.repeat(600);
    const cim = mapToCim(normalizedEvent({ message: longMessage }));
    expect(cim.description).toHaveLength(500);
  });

  test('does not include user/src fields (intentionally omitted — see module header)', () => {
    const cim = mapToCim(normalizedEvent());
    expect(cim).not.toHaveProperty('user');
    expect(cim).not.toHaveProperty('src');
  });

  test('is deterministic — identical input produces identical output', () => {
    const event = normalizedEvent();
    expect(mapToCim(event)).toEqual(mapToCim(event));
  });

  test('never throws on a malformed/empty event', () => {
    expect(() => mapToCim({})).not.toThrow();
    expect(() => mapToCim(null)).not.toThrow();
    expect(() => mapToCim(undefined)).not.toThrow();
  });
});
