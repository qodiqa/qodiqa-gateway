'use strict';

/**
 * remediation — canonical envelope field names + automatic trace
 * correlation.
 *
 * Root cause: services/logger.js built its internal record as
 * { ts, level, event, category, ...extra } while the platform's canonical
 * correlation store (src/core/audit/centralStore.js's platform_audit_events
 * table) and SIEM-shipping normalizer (src/observability/logShipping/
 * schema.js) already used timestamp/severity/eventType — forcing a
 * translation step at ship time instead of the record being canonical from
 * the moment it's created. See SIEM-3-REMEDIATION-REPORT.md.
 *
 * This suite proves:
 *   CE-01..CE-03: emit() produces canonical field names, not the legacy
 *                 ts/level/event names.
 *   CE-04..CE-06: traceId/spanId are populated automatically from the active
 *                 OTel-style span (src/observability/tracing/context.js)
 *                 when tracing is enabled, absent when it is not, and an
 *                 explicit extra.traceId always wins over the inferred one.
 */

let stdoutSpy;
const written = [];

beforeAll(() => {
  const capture = data => {
    for (const line of String(data).split('\n')) {
      if (!line.trim()) continue;
      try { written.push(JSON.parse(line)); } catch { /* ignore */ }
    }
  };
  stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(data => { capture(data); return true; });
});

afterAll(() => {
  stdoutSpy.mockRestore();
});

beforeEach(() => { written.length = 0; });

function lastRecord() { return written[written.length - 1]; }

const { emit, flush } = require('../logger');
const { runWithContext } = require('../../src/observability/tracing/context');

describe('CE-01..CE-03: canonical envelope field names', () => {
  test('CE-01 emit() uses "timestamp", not "ts"', async () => {
    emit('INFO', 'CE_TEST', {});
    await flush();
    const r = lastRecord();
    expect(typeof r.timestamp).toBe('string');
    expect(r.ts).toBeUndefined();
  });

  test('CE-02 emit() uses "severity", not "level"', async () => {
    emit('WARN', 'CE_TEST', {});
    await flush();
    const r = lastRecord();
    expect(r.severity).toBe('WARN');
    expect(r.level).toBeUndefined();
  });

  test('CE-03 emit() uses "eventType", not "event"', async () => {
    emit('INFO', 'CE_TEST_EVENT', {});
    await flush();
    const r = lastRecord();
    expect(r.eventType).toBe('CE_TEST_EVENT');
    expect(r.event).toBeUndefined();
  });
});

describe('CE-04..CE-06: automatic trace correlation', () => {
  test('CE-04 traceId/spanId are absent when no tracing context is active', async () => {
    emit('INFO', 'CE_NO_TRACE', {});
    await flush();
    const r = lastRecord();
    expect(r.traceId).toBeUndefined();
    expect(r.spanId).toBeUndefined();
  });

  test('CE-05 traceId/spanId are populated automatically from the active span', async () => {
    await runWithContext({ traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), sampled: true }, async () => {
      emit('INFO', 'CE_TRACED', {});
      await flush();
    });
    const r = lastRecord();
    expect(r.traceId).toBe('a'.repeat(32));
    expect(r.spanId).toBe('b'.repeat(16));
  });

  test('CE-06 an explicit traceId in extra overrides the inferred one', async () => {
    await runWithContext({ traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), sampled: true }, async () => {
      emit('INFO', 'CE_TRACE_OVERRIDE', { traceId: 'c'.repeat(32) });
      await flush();
    });
    const r = lastRecord();
    expect(r.traceId).toBe('c'.repeat(32));
  });
});

describe('the envelope cannot be overwritten by caller fields', () => {
  test('CE-07 a caller detail named eventType/severity/timestamp/category does not replace the envelope; it is kept under shadowedFields', async () => {
    emit('WARN', 'WEBHOOK_DISPATCH_FAILED', { eventType: 'attestation.completed', severity: 'INFO', timestamp: 'forged', category: 'x', id: 'a1' });
    await flush();
    const r = lastRecord();
    expect(r.eventType).toBe('WEBHOOK_DISPATCH_FAILED');
    expect(r.severity).toBe('WARN');
    expect(r.timestamp).not.toBe('forged');
    expect(r.category).not.toBe('x');
    expect(r.shadowedFields).toEqual({ eventType: 'attestation.completed', severity: 'INFO', timestamp: 'forged', category: 'x' });
    expect(r.id).toBe('a1');
  });

  test('CE-08 control: no collision → no shadowedFields, envelope keys first', async () => {
    emit('INFO', 'CE_TEST', { a: 1 });
    await flush();
    const r = lastRecord();
    expect(r.shadowedFields).toBeUndefined();
    expect(Object.keys(r).slice(0, 4)).toEqual(['timestamp', 'severity', 'eventType', 'category']);
  });
});
