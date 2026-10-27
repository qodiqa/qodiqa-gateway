'use strict';

/**
 * /dashboard — Operational Dashboard API.
 *
 * All routes are protected by opsIpAllowlist + opsAuth + opsGate middleware
 * applied in server.js — no per-route auth here.
 *
 * GET /dashboard/overview     Summary counts (cached 30s)
 * GET /dashboard/executions   Recent allowed executions (paginated)
 * GET /dashboard/blocked      Recent blocked requests + by-reason breakdown
 * GET /dashboard/replays      Replay attempts
 * GET /dashboard/anomalies    Anomaly events + by-type breakdown
 * GET /dashboard/status       Component health
 * GET /dashboard/activity     Time-series request activity
 * GET /dashboard/stream       SSE real-time event stream
 */

const { Router } = require('express');
const agg        = require('../../dashboard/aggregator');
const { getStatus } = require('../../dashboard/statusChecker');
const sseManager    = require('../../dashboard/sseManager');
const { success, failure } = require('../response');
const { parsePagination, withPaginationMeta } = require('../../utils/pagination');

const router = Router();

const DASHBOARD_PAGE_OPTS = { defaultPageSize: 50, maxPageSize: 200 };

// ── Overview ──────────────────────────────────────────────────────────────────

router.get('/overview', (_req, res) => {
  const overview = agg.getOverview();
  const status   = getStatus();
  success(res, {
    ...overview,
    executionIntegrity: status.executionIntegrity,
    uptime:             status.uptime,
  });
});

// ── Executions ────────────────────────────────────────────────────────────────

router.get('/executions', (req, res) => {
  const { page, pageSize } = parsePagination(req.query, DASHBOARD_PAGE_OPTS);
  success(res, withPaginationMeta(agg.getExecutions({ page, pageSize })));
});

// ── Blocked ───────────────────────────────────────────────────────────────────

router.get('/blocked', (req, res) => {
  const { page, pageSize } = parsePagination(req.query, DASHBOARD_PAGE_OPTS);
  success(res, withPaginationMeta(agg.getBlocked({ page, pageSize })));
});

// ── Replays ───────────────────────────────────────────────────────────────────

router.get('/replays', (req, res) => {
  const { page, pageSize } = parsePagination(req.query, DASHBOARD_PAGE_OPTS);
  success(res, withPaginationMeta(agg.getReplays({ page, pageSize })));
});

// ── Anomalies ─────────────────────────────────────────────────────────────────

router.get('/anomalies', (req, res) => {
  const { page, pageSize } = parsePagination(req.query, DASHBOARD_PAGE_OPTS);
  success(res, withPaginationMeta(agg.getAnomalies({ page, pageSize })));
});

// ── System Status ─────────────────────────────────────────────────────────────

router.get('/status', (_req, res) => {
  success(res, getStatus());
});

// ── Activity ──────────────────────────────────────────────────────────────────

router.get('/activity', (req, res) => {
  const windowMinutes = Math.min(1440, Math.max(1, parseInt(req.query.windowMinutes, 10) || 60));
  success(res, agg.getActivity({ windowMinutes }));
});

// ── SSE Stream ────────────────────────────────────────────────────────────────

router.get('/stream', (req, res) => {
  res.set({
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no',   // disable nginx buffering
  });
  res.flushHeaders();

  const id = sseManager.addClient(res);

  req.on('close',   () => sseManager.removeClient(id));
  req.on('aborted', () => sseManager.removeClient(id));
});

// ── 405 catch-all — reject unsupported methods/paths under this mount ────────
router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

module.exports = router;
