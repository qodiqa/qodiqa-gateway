'use strict';

const express          = require('express');
const router           = express.Router();
const nonceStore       = require('../../validation/nonceStore');
const anomalyStore     = require('../../validation/anomalyStore');
const rateLimitStore   = require('../../../services/policy/store');
const readinessState   = require('../../runtime/readinessState');
const pgPool           = require('../../infra/postgres/pool');
const consentSubscriber = require('../../core/consent/revocation/RevocationSubscriber');
const consentCache      = require('../../core/consent/ConsentCache');
const eventLoopMonitor   = require('../../runtime/eventLoopMonitor');
const redisPersistenceMonitor = require('../../infra/redis/persistenceMonitor');
const latencySlaMonitor = require('../../observability/latencySlaMonitor');
const keyExpiryMonitor  = require('../../../services/artifact/keyExpiryMonitor');

let _version = 'unknown';
try { _version = require('../../../package.json').version; } catch { /* ignore */ }

router.get('/', (_req, res) => {
  const nonceReady        = nonceStore.isReady();
  const anomalyReady      = anomalyStore.isReady();
  const rlReady           = rateLimitStore.isReady();
  // PostgreSQL is only a mandatory dependency when this deployment actually
  // uses it (see src/api/routes/ready.js — READY-50); a fully authenticated
  // endpoint, so the underlying technology name is fine to disclose here
  // (unlike /ready — see healthContentSafety.test.js).
  const pgReady            = !pgPool.isEnabled() || pgPool.isHealthy();
  const consentSubReady    = consentSubscriber.isReady();
  // ConsentCache is deliberately excluded from `allReady` /
  // executionIntegrity, matching /ready's REQUIRED_COMPONENTS gating — see
  // the classification comment in src/api/routes/ready.js. It is still
  // surfaced below (required: false) for operational visibility: a
  // prolonged cache outage doesn't break correctness but does shift load
  // onto PostgreSQL, which operators should be able to see coming.
  const consentCacheReady  = consentCache.isReady();
  const allReady           = nonceReady && anomalyReady && rlReady && pgReady && consentSubReady;

  // Lightweight, synchronous pool telemetry — pgPool.waitingCount and
  // friends, read straight off the pg.Pool instance, zero additional query.
  // See src/infra/postgres/pool.js's poolStats() for what "saturated" means.
  const pgPoolStats = pgPool.poolStats();

  res.status(200).json({
    service:            'qodiqa',
    version:            _version,
    status:             readinessState.isReady() ? 'ready' : 'not_ready',
    executionIntegrity: allReady ? 'FULL' : 'DEGRADED',
    uptime:             process.uptime(),
    pid:                process.pid,
    nodeVersion:        process.version,
    components: {
      nonceStore:          { name: 'Nonce Store (Replay Protection)',        ready: nonceReady,     required: true  },
      anomalyStore:        { name: 'Anomaly Store (Burst Detection)',        ready: anomalyReady,   required: true  },
      rateLimitStore:      { name: 'Rate Limit Store (Policy Enforcement)',  ready: rlReady,         required: true  },
      postgres:            {
        name:     'PostgreSQL (Persistence)',
        ready:    pgReady,
        enabled:  pgPool.isEnabled(),
        required: true,
        pool:     pgPoolStats,
      },
      consentSubscriber:   { name: 'Consent Revocation Subscriber',          ready: consentSubReady, required: true  },
      consentCache:        { name: 'Consent Cache (Redis, best-effort)',     ready: consentCacheReady, required: false },
    },
    // Event Loop Delay Monitor — read live off the running
    // perf_hooks histogram, never reset by reading it. Informational only:
    // deliberately NOT folded into executionIntegrity/allReady above, same
    // treatment as consentCache — see src/runtime/eventLoopMonitor.js.
    eventLoop: {
      enabled: eventLoopMonitor.isEnabled(),
      state:   eventLoopMonitor.getState(),
      ...eventLoopMonitor.getStats(),
    },
    // Periodic Redis Durability Validator — read live off the
    // monitor's last completed check, never triggers a new one. Informational
    // only: deliberately NOT folded into executionIntegrity/allReady above,
    // same treatment as eventLoop — see src/infra/redis/persistenceMonitor.js.
    // Note: getStats() already includes `state` — no separate getState()
    // call needed here (unlike eventLoop above, whose getStats() doesn't).
    redisPersistence: {
      enabled: redisPersistenceMonitor.isEnabled(),
      ...redisPersistenceMonitor.getStats(),
    },
    // #9 — same informational-only treatment as eventLoop/redisPersistence above.
    latencySla: {
      enabled: latencySlaMonitor.isEnabled(),
      ...latencySlaMonitor.getState(),
    },
    keyExpiryMonitor: {
      enabled: keyExpiryMonitor.isEnabled(),
    },
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
