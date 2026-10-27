'use strict';

/**
 * GET /health/redis — Redis High-Availability health reporting.
 *
 * Reports per-store connection health for every one of the 9 Redis-backed
 * control planes (nonce, anomaly, rateLimit, rateLimitPolicy, consentCache,
 * revocationPublisher, revocationSubscriber, keyRotationLock,
 * persistenceQueue): mode (single/sentinel/cluster), current master/replica
 * identity (when known), connection state (HEALTHY/DEGRADED/DISCONNECTED/
 * RECOVERING), reconnect/failover counters, and connection uptime.
 *
 * Deliberately a NEW, separate route rather than an extension of GET /ready —
 * see src/infra/redis/health.js's header for why /ready's existing response
 * contract is left untouched.
 *
 * Mounted behind the same protected ops stack as /health and /ready
 * (rate-limited, IP-allowlisted, optionally loopback/auth-gated) — see
 * server.js.
 */

const express = require('express');
const healthRegistry = require('../../infra/redis/health');
const router = express.Router();

const STATUS_HTTP_CODE = Object.freeze({
  healthy:      200,
  recovering:   200,
  degraded:     200,
  disconnected: 503,
});

router.get('/', (_req, res) => {
  const stores  = healthRegistry.getAllHealth();
  const overall = healthRegistry.getOverallStatus();
  const status  = STATUS_HTTP_CODE[overall] ?? 503;

  res.status(status).json({ status: overall, stores });
});

module.exports = router;
