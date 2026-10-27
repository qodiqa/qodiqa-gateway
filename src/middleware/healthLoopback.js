'use strict';

// Optional loopback-only restriction for liveness/readiness probe endpoints.
//
// Kubernetes' kubelet connects to a Pod's IP over the pod network — never via
// loopback — so this control CANNOT be the default gate for /health and
// /ready (enabling it unconditionally would break every Kubernetes
// deployment, identically to the bug this remediation fixes). It exists for
// operators who run QODIQA under Docker/Compose/bare-metal ONLY, where the
// sole legitimate prober (Docker's HEALTHCHECK, or a local health-check
// script) is guaranteed to originate from the container's own loopback
// interface.
//
// Security-critical detail: this check reads req.socket.remoteAddress
// directly. It deliberately does NOT use req.clientIp (middleware/clientIp.js)
// or any X-Forwarded-For / X-Real-IP derived value, because those headers
// are attacker-controlled on any request that reaches this process directly
// — middleware/clientIp.js honours forwarded headers unconditionally for
// logging purposes and must never be treated as an authorization signal.
// Trusting a forwarded header here would let any external client bypass
// loopback verification simply by sending "X-Forwarded-For: 127.0.0.1".
//
// Disabled by default (QODIQA_HEALTH_REQUIRE_LOOPBACK=false).

const { emit } = require('../../services/logger');

function _isLoopback(addr) {
  if (typeof addr !== 'string' || !addr) return false;
  const a = addr.startsWith('::ffff:') ? addr.slice(7) : addr;
  return a === '127.0.0.1' || a === '::1' || a.startsWith('127.');
}

/**
 * @param {object} opsConfig — result of loadOpsConfig()
 */
function createHealthLoopbackMiddleware(opsConfig) {
  if (!opsConfig.healthRequireLoopback) {
    return function healthLoopbackDisabled(_req, _res, next) { next(); };
  }

  return function healthLoopback(req, res, next) {
    const socketIp = req.socket?.remoteAddress ?? null;

    if (!_isLoopback(socketIp)) {
      emit('WARN', 'HEALTH_PROBE_NON_LOOPBACK_BLOCKED', {
        path:      req.path,
        socketIp,
        requestId: req.requestId ?? null,
      });
      return res.status(403).json({
        decision:  'BLOCK',
        reason:    'FORBIDDEN',
        details:   {},
        requestId: req.requestId ?? null,
      });
    }

    next();
  };
}

module.exports = { createHealthLoopbackMiddleware, _isLoopback };
