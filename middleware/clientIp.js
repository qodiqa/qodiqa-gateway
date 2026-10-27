'use strict';

const { resolveClientIp, parseTrustedProxyConfig } = require('../src/infra/network/clientIpResolver');

/**
 * Attach req.clientIp before any business logic runs.
 *
 * SECURITY: X-Forwarded-For / X-Real-IP are attacker-controlled unless the
 * immediate TCP peer is a trusted proxy (see src/infra/network/clientIpResolver.js
 * for the full trust model — the Protocol Specification is silent on this,
 * so industry best practice is followed and documented there).
 *
 * Trust configuration is read from TRUSTED_PROXY — the SAME env var and
 * parsing server.js uses for Express's own `trust proxy` setting, so both
 * mechanisms always agree on which proxies are trusted.
 *
 * Priority:
 *   1. First untrusted hop found while walking the forwarding chain from a
 *      trusted immediate peer (see resolveClientIp) — only when the peer
 *      itself is trusted.
 *   2. TCP remote address — always used when the immediate peer is untrusted,
 *      or as the final fallback.
 *   3. null (unknown — treat as UNKNOWN, never as trusted).
 *
 * Downstream code MUST check req.clientIp !== null before granting IP-based
 * decisions. A null value means the origin is unknown, not that it is safe.
 * req.clientIp MUST NOT be used as an authorization signal on its own (see
 * src/middleware/healthLoopback.js for why loopback-only checks read
 * req.socket.remoteAddress directly instead).
 */
module.exports = function attachClientIp(req, _res, next) {
  req.clientIp = resolveClientIp(req, parseTrustedProxyConfig());
  next();
};

// Exported for unit tests — not part of the public middleware contract.
module.exports._resolveClientIp = resolveClientIp;
