'use strict';

/** HTTP root spans honour the sample rate; spans are flushed periodically, not only at batchSize/shutdown. */

const { createTracer } = require('../tracer');
const { createRequestTracingMiddleware } = require('../middleware');

function run(tracer, headers = {}) {
  const mw = createRequestTracingMiddleware(tracer);
  const handlers = {};
  const res = { statusCode: 200, setHeader() {}, on: (e, f) => { handlers[e] = f; } };
  const req = { method: 'GET', url: '/x', headers, requestId: 'r' };
  mw(req, res, () => {});
  handlers.finish();
  return req;
}

describe('tracing — sample rate and periodic flush', () => {
  test('TR-01 sample rate 0: HTTP root spans are NOT exported (was: always exported)', async () => {
    const exported = [];
    const tracer = createTracer({ sampleRate: 0, batchSize: 1, flushIntervalMs: 0 }, { exporter: { name: 'mem', exportSpans: async (b) => { exported.push(...b); } } });
    for (let i = 0; i < 5; i++) run(tracer);
    await tracer.forceFlush();
    expect(exported).toHaveLength(0);
  });

  test('TR-02 sample rate 1: HTTP root spans are exported; an upstream "not sampled" traceparent is still honoured', async () => {
    const exported = [];
    const tracer = createTracer({ sampleRate: 1, batchSize: 1000, flushIntervalMs: 0 }, { exporter: { name: 'mem', exportSpans: async (b) => { exported.push(...b); } } });
    run(tracer);
    run(tracer, { traceparent: '00-' + 'a'.repeat(32) + '-' + 'b'.repeat(16) + '-00' });
    await tracer.forceFlush();
    expect(exported).toHaveLength(1);
  });

  test('TR-03 a periodic flush exports spans although batchSize was not reached and nobody called shutdown', async () => {
    jest.useFakeTimers();
    try {
      const exported = [];
      const tracer = createTracer({ sampleRate: 1, batchSize: 1000, flushIntervalMs: 50 }, { exporter: { name: 'mem', exportSpans: async (b) => { exported.push(...b); } } });
      run(tracer);
      expect(exported).toHaveLength(0);
      await jest.advanceTimersByTimeAsync(60);
      expect(exported).toHaveLength(1);
      await tracer.shutdown();
    } finally { jest.useRealTimers(); }
  });
});
