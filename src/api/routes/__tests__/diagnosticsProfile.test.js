'use strict';

/**
 * #4 — GET/POST /diagnostics/profile/* route tests.
 *
 * Auth/kill-switch behavior (404 on unauthenticated/disabled) is covered by
 * src/middleware/__tests__/profilingEnabled.test.js and
 * src/middleware/adminProtection.test.js's stack-composition tests — this
 * file covers the route handlers themselves: response shape, duration
 * clamping, and that only the summarized (never raw) profiler output is
 * ever returned.
 */

jest.mock('../../../profiling/memoryProfiler', () => ({
  getHeapStatistics:      jest.fn(() => ({ total_heap_size: 12345 })),
  getHeapSpaceStatistics: jest.fn(() => [{ space_name: 'new_space', space_size: 100 }]),
}));
jest.mock('../../../profiling/gcProfiler', () => ({
  profileGc: jest.fn(),
  analyseGcPressure: jest.fn(() => 'Low'),
}));
jest.mock('../../../profiling/cpuProfiler', () => ({
  profileCpu: jest.fn(),
}));

const request = require('supertest');
const express = require('express');
const diagnosticsProfileRouter = require('../diagnosticsProfile');
const memoryProfiler = require('../../../profiling/memoryProfiler');
const gcProfiler      = require('../../../profiling/gcProfiler');
const cpuProfiler     = require('../../../profiling/cpuProfiler');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.requestId = 'test-req-id'; res.locals.requestId = 'test-req-id'; next(); });
  app.use('/diagnostics/profile', diagnosticsProfileRouter);
  return app;
}

beforeEach(() => jest.clearAllMocks());

describe('GET /diagnostics/profile/memory', () => {
  test('returns heap statistics and heap space statistics, synchronously, with no delay', async () => {
    const res = await request(makeApp()).get('/diagnostics/profile/memory');

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({
      heapStatistics:      { total_heap_size: 12345 },
      heapSpaceStatistics: [{ space_name: 'new_space', space_size: 100 }],
    });
  });

  test('failure in the profiler module returns 500 with a generic PROFILING_FAILED code, without leaking err.message', async () => {
    memoryProfiler.getHeapStatistics.mockImplementation(() => { throw new Error('boom at /internal/secret/path.js:99'); });

    const res = await request(makeApp()).get('/diagnostics/profile/memory');

    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('PROFILING_FAILED');
    expect(JSON.stringify(res.body)).not.toContain('boom');
    expect(JSON.stringify(res.body)).not.toContain('/internal/secret/path.js');
  });
});

describe('GET /diagnostics/profile/gc', () => {
  test('returns the summary and pressure classification, not raw GC events', async () => {
    gcProfiler.profileGc.mockResolvedValue({
      available: true,
      summary: { count: 3, totalPauseMs: 5, meanPauseMs: 1.6, maxPauseMs: 2, pausePercent: 1, byType: {} },
    });

    const res = await request(makeApp()).get('/diagnostics/profile/gc?windowMs=1000');

    expect(res.status).toBe(200);
    expect(res.body.data.pressure).toBe('Low');
    expect(res.body.data.summary).toEqual({ count: 3, totalPauseMs: 5, meanPauseMs: 1.6, maxPauseMs: 2, pausePercent: 1, byType: {} });
    expect(res.body.data.windowMs).toBe(1000);
  });

  test('windowMs is clamped to the minimum (1000ms) when a smaller value is requested', async () => {
    gcProfiler.profileGc.mockResolvedValue({ available: true, summary: {} });

    const res = await request(makeApp()).get('/diagnostics/profile/gc?windowMs=10');

    expect(res.body.data.windowMs).toBe(1000);
  });

  test('windowMs is clamped to the maximum (30000ms) when an oversized value is requested — never hangs past the clamp', async () => {
    gcProfiler.profileGc.mockResolvedValue({ available: true, summary: {} });

    const res = await request(makeApp()).get('/diagnostics/profile/gc?windowMs=999999');

    expect(res.body.data.windowMs).toBe(30_000);
  });

  test('a non-numeric windowMs falls back to the default (5000ms)', async () => {
    gcProfiler.profileGc.mockResolvedValue({ available: true, summary: {} });

    const res = await request(makeApp()).get('/diagnostics/profile/gc?windowMs=not-a-number');

    expect(res.body.data.windowMs).toBe(5_000);
  });

  test('pressure is "Unknown" when the GC observer is unavailable', async () => {
    gcProfiler.profileGc.mockResolvedValue({ available: false, summary: null });

    const res = await request(makeApp()).get('/diagnostics/profile/gc');

    expect(res.body.data.pressure).toBe('Unknown');
    expect(gcProfiler.analyseGcPressure).not.toHaveBeenCalled();
  });
});

describe('POST /diagnostics/profile/cpu', () => {
  test('returns only the summarized hot-node output, never the raw .cpuprofile', async () => {
    cpuProfiler.profileCpu.mockResolvedValue({
      available: true,
      profile: { nodes: ['huge-raw-v8-profile-tree'], samples: [1, 2, 3] },
      summary: { totalSamples: 3, durationMs: 1000, hotNodes: [{ functionName: 'foo', hits: 2 }] },
    });

    const res = await request(makeApp()).post('/diagnostics/profile/cpu').send({ durationMs: 1000 });

    expect(res.status).toBe(200);
    expect(res.body.data.summary).toEqual({ totalSamples: 3, durationMs: 1000, hotNodes: [{ functionName: 'foo', hits: 2 }] });
    expect(res.body.data).not.toHaveProperty('profile');
    expect(JSON.stringify(res.body)).not.toContain('huge-raw-v8-profile-tree');
  });

  test('durationMs is clamped to the maximum (30000ms)', async () => {
    cpuProfiler.profileCpu.mockResolvedValue({ available: true, summary: {} });

    const res = await request(makeApp()).post('/diagnostics/profile/cpu').send({ durationMs: 999999 });

    expect(res.body.data.durationMs).toBe(30_000);
    expect(cpuProfiler.profileCpu).toHaveBeenCalledTimes(1);
  });

  test('durationMs is clamped to the minimum (1000ms)', async () => {
    cpuProfiler.profileCpu.mockResolvedValue({ available: true, summary: {} });

    const res = await request(makeApp()).post('/diagnostics/profile/cpu').send({ durationMs: 1 });

    expect(res.body.data.durationMs).toBe(1_000);
  });

  test('missing durationMs falls back to the default (5000ms)', async () => {
    cpuProfiler.profileCpu.mockResolvedValue({ available: true, summary: {} });

    const res = await request(makeApp()).post('/diagnostics/profile/cpu').send({});

    expect(res.body.data.durationMs).toBe(5_000);
  });

  test('failure in the profiler module returns 500 with a generic PROFILING_FAILED code, no error internals leaked', async () => {
    cpuProfiler.profileCpu.mockRejectedValue(new Error('inspector session conflict at /internal/path.js:42'));

    const res = await request(makeApp()).post('/diagnostics/profile/cpu').send({ durationMs: 1000 });

    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('PROFILING_FAILED');
    expect(JSON.stringify(res.body)).not.toContain('inspector session conflict');
    expect(JSON.stringify(res.body)).not.toContain('/internal/path.js');
  });
});
