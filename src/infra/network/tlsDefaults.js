'use strict';

/**
 * HTTP Server Transport Hardening —
 *
 * Node.js HTTP servers are vulnerable to a class of slow-client attacks
 * (Slowloris, slow-body, keep-alive exhaustion) if connection and request
 * timeouts are not configured.  By default Node.js keeps connections alive
 * indefinitely.
 *
 * This module exports configureTlsDefaults(server) which applies transport-
 * level hardening to an existing http.Server instance:
 *
 *   server.keepAliveTimeout   — 65 s (above typical proxy keep-alive of 60 s)
 *   server.headersTimeout     — 66 s (must be > keepAliveTimeout)
 *   server.requestTimeout     — configurable via REQUEST_TIMEOUT_MS (default 120 s)
 *   server.maxHeadersCount    — 100 (prevents header-flood attacks)
 *   server.connectionsCheckingInterval — configurable via
 *     CONNECTIONS_CHECKING_INTERVAL_MS (default 1 s). This is the real
 *     enforcement mechanism behind requestTimeout: Node closes an
 *     already-expired connection at the next periodic sweep tick, not at
 *     the precise deadline — so the actual worst-case overshoot is bounded
 *     by this interval, not by requestTimeout's own value. Node's own
 *     default (30 s) means an unconfigured server can hold a slow/idle
 *     connection open up to 30 s past its stated requestTimeout deadline
 *.
 *     MUST be applied to the server object before .listen() is called —
 *     Node arms the sweep's real period at/before that point; a later
 *     reassignment (e.g. inside a .listen() callback) has no effect on the
 *     already-created timer, confirmed empirically in the same section.
 *
 * TLS minimum version is Node.js 22's built-in default (TLS 1.2).  Node.js
 * 22 does not negotiate SSLv3 or TLS 1.0/1.1 by default.  No override is
 * needed here; this behaviour is documented in the THREAT MODEL.
 *
 * Connection-level limits:
 *   server.maxConnections is deliberately NOT set because the correct limit
 *   depends on the deployment topology (number of reverse proxy workers,
 *   health-check frequency, etc.).  Set it via MAX_HTTP_CONNECTIONS if needed.
 *   The default (unlimited at the Node.js level) is safe when QODIQA is
 *   behind a properly configured load balancer with its own connection limits.
 *
 * Emits a structured startup event describing the applied configuration.
 */

const DEFAULT_KEEP_ALIVE_TIMEOUT_MS = 65_000;
const DEFAULT_HEADERS_TIMEOUT_MS    = 66_000;
const DEFAULT_REQUEST_TIMEOUT_MS    = 120_000;
const DEFAULT_MAX_HEADERS_COUNT     = 100;
const DEFAULT_CONNECTIONS_CHECKING_INTERVAL_MS = 1_000;

/**
 * Applies transport hardening to the given http.Server.
 * MUST be called BEFORE `server.listen()` — see connectionsCheckingInterval's
 * own doc comment above for why.
 *
 * @param {import('http').Server} server - The (not-yet-listening) HTTP server.
 * @param {Function} emit - Structured log emitter (emit(level, event, data)).
 */
function configureTlsDefaults(server, emit) {
  const keepAliveTimeout = _parseInt(process.env.KEEP_ALIVE_TIMEOUT_MS, DEFAULT_KEEP_ALIVE_TIMEOUT_MS);
  const headersTimeout   = _parseInt(process.env.HEADERS_TIMEOUT_MS,    DEFAULT_HEADERS_TIMEOUT_MS);
  const requestTimeout   = _parseInt(process.env.REQUEST_TIMEOUT_MS,    DEFAULT_REQUEST_TIMEOUT_MS);
  const maxHeadersCount  = _parseInt(process.env.MAX_HEADERS_COUNT,     DEFAULT_MAX_HEADERS_COUNT);
  const connectionsCheckingInterval = _parseInt(
    process.env.CONNECTIONS_CHECKING_INTERVAL_MS, DEFAULT_CONNECTIONS_CHECKING_INTERVAL_MS,
  );
  const maxConnections   = process.env.MAX_HTTP_CONNECTIONS
    ? _parseInt(process.env.MAX_HTTP_CONNECTIONS, 0)
    : null;

  if (headersTimeout <= keepAliveTimeout) {
    const msg =
      `HEADERS_TIMEOUT_MS (${headersTimeout}) must be greater than ` +
      `KEEP_ALIVE_TIMEOUT_MS (${keepAliveTimeout}).  ` +
      `Node.js requires headersTimeout > keepAliveTimeout to avoid a race ` +
      `condition where keep-alive requests time out before headers are received.`;
    if (emit) emit('FATAL', 'TLS_DEFAULTS_CONFIG_ERROR', { message: msg });
    throw new Error(msg);
  }

  server.keepAliveTimeout = keepAliveTimeout;
  server.headersTimeout   = headersTimeout;
  server.requestTimeout   = requestTimeout;
  server.maxHeadersCount  = maxHeadersCount;
  server.connectionsCheckingInterval = connectionsCheckingInterval;

  if (maxConnections !== null && maxConnections > 0) {
    server.maxConnections = maxConnections;
  }

  if (emit) {
    emit('INFO', 'HTTP_SERVER_TRANSPORT_HARDENED', {
      keepAliveTimeoutMs:  keepAliveTimeout,
      headersTimeoutMs:    headersTimeout,
      requestTimeoutMs:    requestTimeout,
      maxHeadersCount,
      connectionsCheckingIntervalMs: connectionsCheckingInterval,
      maxConnections:      maxConnections ?? '(unlimited — set MAX_HTTP_CONNECTIONS to cap)',
      tlsMinVersion:       'TLS 1.2 (Node.js 22 default — no SSLv3/TLS1.0/TLS1.1)',
    });
  }
}

function _parseInt(raw, fallback) {
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

module.exports = { configureTlsDefaults };
