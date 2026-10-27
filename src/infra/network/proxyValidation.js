'use strict';

/**
 * Trusted Proxy Validation —
 *
 * QODIQA is designed to run behind a reverse proxy (nginx, caddy, ALB, etc.)
 * that terminates TLS and forwards requests over HTTP.  The proxy attaches
 * X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host headers that
 * QODIQA trusts for client IP extraction and protocol validation.
 *
 * Without explicit validation, an attacker who can reach the application
 * directly (bypassing the proxy) can forge these headers and:
 *   • Spoof their source IP to bypass IP blocklists
 *   • Claim HTTPS when the request arrived over plain HTTP
 *   • Inject a crafted Host header to poison cache keys or URL generation
 *   • Extend the X-Forwarded-For chain beyond the expected depth
 *
 * This module provides:
 *
 *   validateProxyConfig(env)
 *     Called at startup.  Emits warnings if the proxy trust configuration
 *     looks insecure (e.g., trusting all proxies with TRUSTED_PROXY=*).
 *     Returns a summary object consumed by GATEWAY_START diagnostics.
 *
 *   createProxyValidationMiddleware(opts)
 *     Returns per-request Express middleware that validates:
 *       1. X-Forwarded-For chain depth (max configurable, default 10)
 *       2. X-Forwarded-Proto is 'https' in production (when enforced); an absent
 * one is refused when a trusted proxy forwarded the request
 *       3. Host header against an allowed-host allowlist (when configured)
 *
 * Deployment assumptions documented here:
 *   • TRUSTED_PROXY should list only the reverse proxy's IP(s) or CIDR range.
 *   • The reverse proxy must strip all client-supplied X-Forwarded-* headers
 *     before adding its own.  This is the responsibility of the proxy operator.
 *   • QODIQA_ALLOWED_HOSTS (comma-separated) restricts the Host header to
 *     expected values.  Leave unset to allow any host (development only).
 *   • ENFORCE_HTTPS_PROTO=true (default in production) rejects requests where
 *     X-Forwarded-Proto is not 'https'.
 *
 * See docs/security/THREAT_MODEL.md §Trust Boundaries for full analysis.
 */

const net = require('net');

// Maximum X-Forwarded-For chain depth we will accept.  A legitimate request
// through a single reverse proxy produces exactly 2 entries (client + proxy).
// More than MAX_FORWARDED_DEPTH entries indicates either a misconfigured proxy
// chain or a client attempting to pad the XFF header to hide their real IP.
const MAX_FORWARDED_DEPTH = parseInt(process.env.MAX_FORWARDED_DEPTH || '10', 10);

// Patterns that indicate TRUSTED_PROXY is set to an overly permissive value.
const _WILDCARD_PATTERNS = ['*', '0.0.0.0/0', '::/0', '0.0.0.0', '::'];

/**
 * Validates the proxy trust configuration at startup.
 *
 * @param {object} [env] - Env var map (defaults to process.env).
 * @returns {{ safe: boolean, warnings: string[], summary: object }}
 */
function validateProxyConfig(env) {
  const e        = env || process.env;
  const raw      = e.TRUSTED_PROXY || '';
  const warnings = [];

  // Detect wildcard / trust-all patterns.
  const entries = raw.split(',').map(s => s.trim()).filter(Boolean);
  for (const entry of entries) {
    if (_WILDCARD_PATTERNS.includes(entry.toLowerCase())) {
      warnings.push(
        `TRUSTED_PROXY contains '${entry}' which trusts all upstream IPs. ` +
        `This allows any client to forge X-Forwarded-For, X-Forwarded-Proto, ` +
        `and X-Real-IP headers.  Set TRUSTED_PROXY to the specific IP or CIDR ` +
        `of your reverse proxy instead.`,
      );
    }
  }

  // Warn if TRUSTED_PROXY is unset in production (defaults to private ranges,
  // which is correct for most deployments but should be explicit).
  const isProduction = (e.NODE_ENV || '') === 'production';
  if (isProduction && entries.length === 0) {
    warnings.push(
      `TRUSTED_PROXY is not set in production.  The default (loopback, linklocal, ` +
      `uniquelocal) is safe for single-host deployments but may not match your ` +
      `network topology.  Set TRUSTED_PROXY explicitly for production.`,
    );
  }

  // Warn if ENFORCE_HTTPS_PROTO is explicitly disabled in production.
  if (isProduction && e.ENFORCE_HTTPS_PROTO === 'false') {
    warnings.push(
      `ENFORCE_HTTPS_PROTO=false in production disables X-Forwarded-Proto validation. ` +
      `Clients may reach the API over unencrypted HTTP without detection.`,
    );
  }

  const allowedHosts = _parseAllowedHosts(e.QODIQA_ALLOWED_HOSTS || '');
  if (isProduction && allowedHosts.length === 0) {
    warnings.push(
      `QODIQA_ALLOWED_HOSTS is not set in production.  Set it to the expected ` +
      `hostname(s) of this deployment to prevent host header injection attacks.`,
    );
  }

  return {
    safe: warnings.length === 0,
    warnings,
    summary: {
      trustedProxy:         raw || '(default: none — no proxy is trusted unless TRUSTED_PROXY is set)',
      allowedHosts:         allowedHosts,
      enforceHttpsProto:    e.ENFORCE_HTTPS_PROTO !== 'false',
      maxForwardedDepth:    MAX_FORWARDED_DEPTH,
    },
  };
}

/**
 * Returns Express middleware that validates proxy-injected headers per request.
 *
 * @param {object} [opts]
 * @param {string[]} [opts.allowedHosts]     - Allowed Host header values.
 * @param {boolean}  [opts.enforceHttpsProto]- Reject non-HTTPS proto in production.
 * @param {number}   [opts.maxForwardedDepth]- Max X-Forwarded-For chain length.
 * @returns {Function} Express middleware.
 */
function createProxyValidationMiddleware(opts = {}) {
  const e            = process.env;
  const allowedHosts = opts.allowedHosts    ?? _parseAllowedHosts(e.QODIQA_ALLOWED_HOSTS || '');
  const enforceProto = opts.enforceHttpsProto ?? (e.ENFORCE_HTTPS_PROTO !== 'false');
  const maxDepth     = opts.maxForwardedDepth ?? MAX_FORWARDED_DEPTH;
  // the same trust predicate as Express `trust proxy` / resolveClientIp (TRUSTED_PROXY, default 'loopback').
  const { parseTrustedProxyConfig, _makeTrustPredicate } = require('./clientIpResolver');
  const isTrustedPeer = _makeTrustPredicate(opts.trustedProxy ?? parseTrustedProxyConfig());

  return function proxyValidation(req, res, next) {
    // Read NODE_ENV at request time so tests can override it after middleware creation.
    const isProduction = (process.env.NODE_ENV || '') === 'production';
    // ── 1. X-Forwarded-For chain depth ────────────────────────────────────────
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      const chain = xff.split(',').map(s => s.trim()).filter(Boolean);
      if (chain.length > maxDepth) {
        return res.status(400).json({
          decision:  'BLOCK',
          reason:    'PROXY_CHAIN_TOO_DEEP',
          details:   { depth: chain.length, max: maxDepth },
          requestId: req.requestId ?? null,
        });
      }
      // Each entry in XFF must be a valid IP address.  An invalid entry
      // indicates header injection or proxy misconfiguration.
      for (const entry of chain) {
        if (!net.isIP(entry)) {
          return res.status(400).json({
            decision:  'BLOCK',
            reason:    'INVALID_FORWARDED_IP',
            details:   { entry },
            requestId: req.requestId ?? null,
          });
        }
      }
    }

    // ── 2. X-Forwarded-Proto validation ───────────────────────────────────────
    if (isProduction && enforceProto) {
      const proto = req.headers['x-forwarded-proto'];
      if (proto && proto.toLowerCase() !== 'https') {
        return res.status(400).json({
          decision:  'BLOCK',
          reason:    'INSECURE_PROTOCOL',
          details:   { proto },
          requestId: req.requestId ?? null,
        });
      }
      // an ABSENT X-Forwarded-Proto used to pass unconditionally. A request that a TRUSTED proxy
      // forwarded (the peer is in TRUSTED_PROXY and it carries a forwarding header) without stating the scheme is now
      // treated as not-HTTPS — fail closed. Deliberately NOT extended to:
      //   - a direct TLS connection (req.socket.encrypted) — the scheme is known first-hand;
      //   - a trusted peer that forwarded nothing (no X-Forwarded-For / X-Real-IP / Forwarded) — that is a local
      //     process, e.g. the shipped Compose in-container healthcheck (deploy/docker/docker-compose.prod.yml, a bare
      //     http://localhost:3000/health from loopback, which TRUSTED_PROXY's default 'loopback' trusts);
      //   - an UNTRUSTED peer — e.g. kubelet httpGet probes from the node IP (deploy/kubernetes/overlays/single-node).
      if (!proto && !(req.socket && req.socket.encrypted)) {
        const forwarded = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.headers.forwarded;
        const peer = req.socket ? req.socket.remoteAddress : null;
        if (forwarded && peer && isTrustedPeer(peer)) {
          return res.status(400).json({
            decision:  'BLOCK',
            reason:    'INSECURE_PROTOCOL',
            details:   { proto: null, missingForwardedProto: true },
            requestId: req.requestId ?? null,
          });
        }
      }
    }

    // ── 3. Host header validation ─────────────────────────────────────────────
    if (allowedHosts.length > 0) {
      const host = (req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
      if (!allowedHosts.includes(host)) {
        return res.status(400).json({
          decision:  'BLOCK',
          reason:    'INVALID_HOST_HEADER',
          details:   { host },
          requestId: req.requestId ?? null,
        });
      }
    }

    next();
  };
}

function _parseAllowedHosts(raw) {
  return raw
    .split(',')
    .map(h => h.trim().toLowerCase().replace(/:\d+$/, ''))
    .filter(Boolean);
}

module.exports = { validateProxyConfig, createProxyValidationMiddleware };
