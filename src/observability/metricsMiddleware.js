'use strict';

const metrics = require('./metrics');

function _nowMs() {
  return Number(process.hrtime.bigint()) / 1_000_000;
}

function _recordSecurityEvent(reason) {
  if (!reason) return;
  const event = metrics.REASON_SECURITY_EVENT[reason];
  if (event) metrics.securityEventsTotal.inc({ event });
}

// createEnforcementMiddleware — instruments /ai/chat responses only

function createEnforcementMiddleware() {
  return function enforcementMetrics(req, res, next) {
    const startMs       = _nowMs();
    const _originalJson = res.json.bind(res);

    res.json = function instrumentedJson(body) {
      try {
        if (body && typeof body === 'object' && !Array.isArray(body)) {
          const decision   = body.decision;
          const reason     = body.reason;
          const durationMs = _nowMs() - startMs;

          if (decision === 'EXECUTE') {
            metrics.requestsTotal.inc({ decision: 'EXECUTE' });
            metrics.requestDurationMs.observe({ decision: 'EXECUTE' }, durationMs);
          } else if (decision === 'BLOCK') {
            metrics.requestsTotal.inc({ decision: 'BLOCK' });
            if (reason) {
              metrics.blocksTotal.inc({ reason });
              _recordSecurityEvent(reason);
            }
            metrics.requestDurationMs.observe({ decision: 'BLOCK' }, durationMs);
          }
        }
      } catch { /* metrics must never throw into response path */ }

      return _originalJson(body);
    };

    next();
  };
}

// createVerificationMiddleware — instruments /verify responses only

function createVerificationMiddleware() {
  return function verificationMetrics(req, res, next) {
    const startMs       = _nowMs();
    const _originalJson = res.json.bind(res);

    res.json = function instrumentedJson(body) {
      try {
        if (body && typeof body === 'object' && !Array.isArray(body)) {
          const decision   = body.decision;
          const reason     = body.reason;
          const durationMs = _nowMs() - startMs;

          if (decision === 'EXECUTE') {
            metrics.verificationRequestsTotal.inc({ decision: 'EXECUTE' });
            metrics.verificationDurationMs.observe({ decision: 'EXECUTE' }, durationMs);
          } else if (decision === 'BLOCK') {
            metrics.verificationRequestsTotal.inc({ decision: 'BLOCK' });
            if (reason) metrics.verificationBlocksTotal.inc({ reason });
            metrics.verificationDurationMs.observe({ decision: 'BLOCK' }, durationMs);
          }
        }
      } catch { /* metrics must never throw into response path */ }

      return _originalJson(body);
    };

    next();
  };
}

// 2026-10-06: app-wide response counter. Cardinality is bounded: the family is the first path
// segment only when it is one of the mounted prefixes below, otherwise "other"; the status is reduced to its class.
const ROUTE_FAMILIES = new Set(['ai', 'verify', 'sign', 'health', 'ready', 'metrics', 'diagnostics', '.well-known',
  'public-key', 'public-keys', 'keys', 'audit', 'audit-viewer', 'policy-ui', 'provenance', 'evidence-chain', 'evidence',
  'transparency', 'portal', 'v1', 'dashboard', 'key-admin', 'rbac', 'signing-identities', 'audit-store', 'compliance',
  'alerts', 'consent', 'tenant-portal', 'auth']);
function routeFamily(url) {
  const seg = String(url || '').split('?')[0].split('/')[1] || '';
  return ROUTE_FAMILIES.has(seg) ? seg : 'other';
}
function createHttpResponseMetrics() {
  return function httpResponseMetrics(req, res, next) {
    const url = req.originalUrl || req.url;
    res.once('finish', () => {
      try { metrics.httpResponsesTotal.inc({ route_family: routeFamily(url), status_class: `${Math.floor(res.statusCode / 100)}xx` }); } catch { /* best-effort */ }
    });
    next();
  };
}

module.exports = { createEnforcementMiddleware, createVerificationMiddleware, createHttpResponseMetrics, routeFamily, ROUTE_FAMILIES };
