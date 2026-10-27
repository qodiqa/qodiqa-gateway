'use strict';

// IP allowlist middleware for operational visibility endpoints.
//
// When allowlisting is enabled every request must originate from an IP that
// matches at least one configured allowlist entry (bare IPv4, IPv4 CIDR,
// bare IPv6, or IPv6 CIDR).
//
// Proxy safety:
//   - Forwarded headers (X-Forwarded-For, X-Real-IP) are honoured ONLY when
//     QODIQA_OPS_TRUST_PROXY=true is explicitly set.
//   - The socket remote address is always available as a final fallback.
//   - IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are normalized to plain IPv4.
//
// Fail-closed:
//   - Invalid allowlist configuration → deny all with 403
//   - Empty allowlist with allowlisting enabled → deny all with 403
//   - Unresolvable client IP → deny with 403
//   - CIDR parse failure → deny all with 403

const { emit } = require('../../services/logger');
const { failure } = require('../api/response');
const { resolveClientIp, parseTrustedProxyConfig } = require('../infra/network/clientIpResolver');
// IP/CIDR matcher primitives — single source of truth, shared with
// src/infra/network/clientIpResolver.js. Re-exported below for backward
// compatibility with existing importers of this module.
const {
  _ipToInt,
  _expandIPv6,
  _ipv6ToBigInt,
  _buildIPv6Matcher,
  _buildMatcher,
  _normalizeIp,
} = require('../infra/network/ipMatch');

// ── Middleware factory ────────────────────────────────────────────────────────

// This middleware gates two distinct surfaces that must not share a response
// shape: the unauthenticated health/ready probes (kept as the pipeline
// decision-shape — see server.js's health mounts) and the admin/ops API
// surface (canonical management envelope — src/api/response.js). Callers
// select which one applies via `envelope`; the default preserves the
// pre-existing probe-surface shape so unrelated call sites need no change.
function _deny(res, req, envelope) {
  if (envelope === 'management') {
    return failure(res, 'FORBIDDEN', 'Client IP is not on the allowlist', 403);
  }
  return res.status(403).json({
    decision:  'BLOCK',
    reason:    'FORBIDDEN',
    details:   {},
    requestId: req.requestId ?? null,
  });
}

function createOpsIpAllowlistMiddleware(opsConfig, { envelope = 'probe' } = {}) {
  // If allowlisting is disabled, this middleware is a no-op.
  if (!opsConfig.ipAllowlistEnabled) {
    return (_req, _res, next) => next();
  }

  // Fail-closed: invalid or empty configuration → deny everything.
  if (!opsConfig.allowlistConfigValid || opsConfig.allowlistEntries.length === 0) {
    emit('ERROR', 'OPS_ALLOWLIST_MISCONFIGURED', {
      ipAllowlistEnabled:  opsConfig.ipAllowlistEnabled,
      allowlistConfigValid: opsConfig.allowlistConfigValid,
      entryCount:          opsConfig.allowlistEntries.length,
      message:             'IP allowlist enabled but has no valid entries — all requests will be denied',
    });

    return (req, res) => {
      emit('WARN', 'OPS_ALLOWLIST_BLOCKED', {
        reason:    'allowlist_misconfigured',
        ip:        null,
        path:      req.path,
        requestId: req.requestId ?? null,
      });
      return _deny(res, req, envelope);
    };
  }

  // Compile all allowlist entries into matcher functions.
  // If any entry fails to compile, treat the whole config as invalid.
  const matchers = opsConfig.allowlistEntries.map(_buildMatcher);

  if (matchers.some(m => m === null)) {
    emit('ERROR', 'OPS_ALLOWLIST_COMPILE_ERROR', {
      entries: opsConfig.allowlistEntries,
      message: 'One or more allowlist entries failed to compile — all requests will be denied',
    });
    return (req, res) => _deny(res, req, envelope);
  }

  return function opsIpAllowlist(req, res, next) {
    // the SAME explicit trusted-proxy list as every other
    // consumer (TRUSTED_PROXY, default 'loopback'). this passed
    // `opsConfig.trustProxy === true`, and QODIQA_OPS_TRUST_PROXY=true meant
    // "trust every immediate peer" — so any client could put an allowlisted
    // address in X-Forwarded-For and walk past this allowlist.
    let clientIp = resolveClientIp(req, parseTrustedProxyConfig());

    if (!clientIp) {
      emit('WARN', 'OPS_ALLOWLIST_BLOCKED', {
        reason:    'unresolvable_client_ip',
        ip:        null,
        path:      req.path,
        requestId: req.requestId ?? null,
      });
      return _deny(res, req, envelope);
    }

    const allowed = matchers.some(m => m(clientIp));

    if (!allowed) {
      emit('WARN', 'OPS_ALLOWLIST_BLOCKED', {
        reason:    'ip_not_in_allowlist',
        ip:        clientIp,
        path:      req.path,
        requestId: req.requestId ?? null,
      });
      return _deny(res, req, envelope);
    }

    next();
  };
}

module.exports = {
  createOpsIpAllowlistMiddleware,
  _normalizeIp,
  _buildMatcher,
  _ipToInt,
  _expandIPv6,
  _ipv6ToBigInt,
  _buildIPv6Matcher,
};
