'use strict';

/**
 * Production Diagnostics — Profiling Surface — #4.
 *
 * src/profiling/{cpuProfiler,gcProfiler,memoryProfiler}.js
 * were fully built but only ever consumed by the offline benchmark.js CLI —
 * never wired to an HTTP route. This router exposes them for live production
 * diagnostics, mounted at /diagnostics/profile (deliberately distinct from
 * the existing health-style /diagnostics route — see src/api/routes/
 * diagnostics.js — to avoid colliding with its established meaning).
 *
 * Auth: ctx.opsOnlyStack() (rate limit, IP allowlist, ops auth, general
 * diagnostics gate) PLUS a second, independent kill switch
 * (createProfilingDiagnosticsGate, src/middleware/profilingEnabled.js) — both
 * composed in src/app.js's mount, not here. This file assumes it is only
 * ever reached by an already-authenticated, already-enabled request.
 *
 * Every endpoint is read-only / bounded-duration:
 *   - GET /diagnostics/profile/memory — synchronous v8 heap statistics, zero
 *     side effects, safe by construction.
 *   - GET /diagnostics/profile/gc?windowMs=<n> — observes GC events for a
 *     clamped window, returns a pressure classification + summary.
 *   - POST /diagnostics/profile/cpu {durationMs} — runs a clamped-duration
 *     CPU profile (idle sampling window), returns the SUMMARIZED hot-node
 *     output only — never the raw .cpuprofile JSON, which is a larger
 *     information-disclosure surface (full call tree, every sampled frame).
 *
 * No endpoint here accepts a caller-supplied filesystem path — memoryProfiler
 * .captureHeapSnapshot() (which writes to disk) is deliberately NOT exposed.
 */

const express = require('express');
const router  = express.Router();

const { success, internalError } = require('../response');

const MIN_WINDOW_MS = 1_000;
const MAX_WINDOW_MS = 30_000;
const DEFAULT_WINDOW_MS = 5_000;

function _clamp(value, min, max, fallback) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// GET /diagnostics/profile/memory
router.get('/memory', (req, res) => {
  const memoryProfiler = require('../../profiling/memoryProfiler');
  try {
    const heapStatistics     = memoryProfiler.getHeapStatistics();
    const heapSpaceStatistics = memoryProfiler.getHeapSpaceStatistics();
    return success(res, { heapStatistics, heapSpaceStatistics });
  } catch (err) {
    // Never pass err.message into the client-facing response — it can leak
    // internal implementation details (file paths, stack-adjacent text).
    // Logged server-side by internalError(); response body stays generic.
    return internalError(res, req, err, { label: 'PROFILING_MEMORY_FAILED', code: 'PROFILING_FAILED', message: 'Memory profiling failed' });
  }
});

// GET /diagnostics/profile/gc?windowMs=<n>
router.get('/gc', async (req, res) => {
  const gcProfiler = require('../../profiling/gcProfiler');
  const windowMs = _clamp(req.query.windowMs, MIN_WINDOW_MS, MAX_WINDOW_MS, DEFAULT_WINDOW_MS);

  try {
    const result = await gcProfiler.profileGc(() => _sleep(windowMs), { warmupMs: 0 });
    return success(res, {
      windowMs,
      available: result.available,
      summary:   result.summary,
      pressure:  result.available ? gcProfiler.analyseGcPressure(result.summary) : 'Unknown',
    });
  } catch (err) {
    return internalError(res, req, err, { label: 'PROFILING_GC_FAILED', code: 'PROFILING_FAILED', message: 'GC profiling failed' });
  }
});

// POST /diagnostics/profile/cpu  { durationMs }
router.post('/cpu', async (req, res) => {
  const cpuProfiler = require('../../profiling/cpuProfiler');
  const durationMs = _clamp(req.body?.durationMs, MIN_WINDOW_MS, MAX_WINDOW_MS, DEFAULT_WINDOW_MS);

  try {
    const result = await cpuProfiler.profileCpu(() => _sleep(durationMs));
    // Summarized hot-node output only — never the raw .cpuprofile (result.profile).
    return success(res, {
      durationMs,
      available: result.available,
      summary:   result.summary,
    });
  } catch (err) {
    return internalError(res, req, err, { label: 'PROFILING_CPU_FAILED', code: 'PROFILING_FAILED', message: 'CPU profiling failed' });
  }
});

module.exports = router;
