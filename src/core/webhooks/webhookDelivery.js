'use strict';

/**
 * Webhook Delivery Engine — Component #28 / Security: Component 44.6
 *
 * Performs a single signed HTTPS POST to a webhook endpoint with full
 * outbound security enforcement:
 *
 * SECURITY (Component 44.6):
 *   • SSRF protection: rejects localhost, all RFC-1918 ranges, link-local,
 *     carrier-grade NAT, multicast, reserved, documentation, benchmark,
 *     unique-local IPv6, and all cloud metadata endpoints.
 *   • DNS rebinding protection: resolves hostname twice — once before
 *     connection and once at TCP socket creation — and rejects if the
 *     address set changes between the two resolutions.
 *   • Circuit breaker: per-host CLOSED/OPEN/HALF_OPEN state machine;
 *     rejects immediately when OPEN without opening a connection.
 *   • TLS enforcement: minimum TLSv1.2, strong cipher suites, certificate
 *     verification always enabled.
 *   • Configurable timeouts: connection, TLS, response-headers, total.
 *   • Allowlist / denylist: host, wildcard-domain, and CIDR matching.
 *   • HTTPS-only: all other protocols are rejected before DNS resolution.
 *
 * LEGACY SSRF (backward compatibility):
 *   validateUrl() is preserved and exported for tests and the API layer
 *   which performs URL-only checks before storing an endpoint.  The delivery
 *   path always uses validateDestination() which adds DNS and rebinding checks.
 *
 * SIGNATURE FORMAT:
 *   X-QODIQA-Signature: sha256=<hex>
 *   Signing input: `${timestamp}.${rawBody}`
 *   Receivers can verify by computing the same HMAC with the shared secret.
 */

const https  = require('https');
const crypto = require('crypto');
const net    = require('net');
const { URL } = require('url');
const { emit }    = require('../../../services/logger');
const metrics     = require('./webhookMetrics');
const promMetrics = require('../../observability/metrics');
const store       = require('./webhookStore');
const { logDelivery } = require('./webhookStore');
const {
  validateDestination,
  createSecureLookup,
  buildTlsOptions,
  _blockedIpv4Reason,
  _blockedIpv6Reason,
  _isBlockedHostname,
} = require('./webhookSecurity');
const { defaultConfig }    = require('./webhookSecurityConfig');
const { getCircuitBreaker } = require('./webhookCircuitBreaker');
const { shouldRetry }       = require('./webhookRetryPolicy');

const USER_AGENT = 'QODIQA-Webhooks/1.0';

// ── Legacy SSRF protection (URL-only, synchronous) ────────────────────────────
// Retained for: (a) API-layer endpoint URL validation before storage,
// (b) backward compatibility with existing tests.

// (2026-10-05: the former IPv4/IPv6 prefix regexes are superseded by the shared delivery-time blocklist —
// see validateUrl.)

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
]);

/**
 * Synchronous URL-only SSRF check (pattern-based, no DNS).
 * Used by the API layer when storing an endpoint URL.
 * The delivery path uses validateDestination() instead.
 *
 * @param {string} rawUrl
 * @returns {{ ok: true, parsed: URL } | { ok: false, error: string }}
 */
function validateUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, error: `Invalid URL: ${rawUrl}` };
  }

  if (parsed.protocol !== 'https:') {
    return { ok: false, error: `URL must use HTTPS protocol (got: ${parsed.protocol})` };
  }

  const host = parsed.hostname.toLowerCase();

  // an IP-literal host is checked against the SAME blocklist the
  // delivery path applies to every resolved address (webhookSecurity _blockedIpv4Reason / _blockedIpv6Reason: IPv4
  // private/reserved CIDRs; IPv6 ::/128, ::1, ::/96 IPv4-compatible, ::ffff:0:0/96 IPv4-mapped, NAT64, ULA, link-local,
  // multicast, …). Before, the IPv4-oriented regexes below never matched a bracketed IPv6 literal (`new URL()` keeps
  // the brackets), so `https://[::1]/`, `https://[::7f00:1]/` (::/96) and `https://[::ffff:7f00:1]/` could be
  // REGISTERED; only delivery refused them. A hostname cannot be resolved here once and trusted (DNS can change after
  // registration — rebinding); its resolved addresses are checked at every delivery by validateDestination().
  const bare   = host.replace(/^\[|\]$/g, '');
  const family = net.isIP(bare);
  if (family) {
    const reason = family === 6 ? _blockedIpv6Reason(bare) : _blockedIpv4Reason(bare);
    if (reason) return { ok: false, error: `Blocked private/loopback address: ${reason}` };
    return { ok: true, parsed };
  }

  // Hostnames: the delivery path's hostname rules (exact names and blocked suffixes), plus this module's legacy names.
  // The IPv4/IPv6 prefix regexes are no longer applied to hostnames: they over-blocked ordinary names that merely
  // start with "fc"/"fd"/"fe80" (e.g. fcm.googleapis.com) and added nothing for real IP literals, handled above.
  if (BLOCKED_HOSTNAMES.has(host) || _isBlockedHostname(host)) {
    return { ok: false, error: `Blocked hostname: ${host}` };
  }

  return { ok: true, parsed };
}

// ── HMAC signature ────────────────────────────────────────────────────────────

/**
 * Compute X-QODIQA-Signature value.
 * Input: `${timestamp}.${rawBody}`
 *
 * @param {string} secret     plaintext webhook secret
 * @param {string} timestamp  ISO timestamp string
 * @param {string} rawBody    serialized JSON body
 * @returns {string}  e.g. 'sha256=abc123...'
 */
function computeSignature(secret, timestamp, rawBody) {
  const sig = crypto.createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`)
    .digest('hex');
  return `sha256=${sig}`;
}

// ── Secure HTTP POST ──────────────────────────────────────────────────────────

/**
 * Perform the HTTPS POST to a webhook endpoint with full security enforcement.
 *
 * Security sequence:
 *   1. validateDestination()  — URL parse, protocol, SSRF, DNS, allowlist/denylist
 *   2. Circuit breaker check  — reject immediately if host circuit is OPEN
 *   3. https.request() with DNS re-validation lookup (rebinding protection)
 *      and TLS enforcement
 *   4. Circuit breaker outcome recording
 *
 * @param {object} opts
 * @param {string} opts.url
 * @param {string} opts.secret      plaintext secret (used to sign, never logged)
 * @param {string} opts.eventId
 * @param {string} opts.eventType
 * @param {object} opts.payload
 * @param {object} [opts.config]    optional security config override
 * @returns {Promise<{ ok: boolean, httpStatus: number|null, durationMs: number, error: string|null }>}
 */
async function post({ url, secret, eventId, eventType, payload, config }) {
  const cfg = config ?? defaultConfig;

  // ── 1. Full pre-connection validation (URL + DNS + allowlist/denylist) ──────

  const destResult = await validateDestination(url, cfg);
  if (!destResult.ok) {
    emit('WARN', 'WEBHOOK_DELIVERY_BLOCKED', {
      url,
      eventId,
      eventType,
      reason: destResult.error,
    });
    return { ok: false, httpStatus: null, durationMs: 0, error: destResult.error };
  }

  const { parsedUrl, hostname, addressSetKey } = destResult;

  // ── 2. Circuit breaker ───────────────────────────────────────────────────────

  const cb = getCircuitBreaker(hostname, cfg);
  if (!cb.allowRequest()) {
    const cbError = `Circuit breaker OPEN for ${hostname} — request rejected`;
    emit('WARN', 'WEBHOOK_CIRCUIT_BREAKER_REJECTED', {
      url,
      eventId,
      eventType,
      hostname,
      state: cb.state,
    });
    return { ok: false, httpStatus: null, durationMs: 0, error: cbError };
  }

  // ── 3. Build request ─────────────────────────────────────────────────────────

  const timestamp = new Date().toISOString();
  const rawBody   = JSON.stringify(payload);
  const signature = computeSignature(secret, timestamp, rawBody);

  const headers = {
    'Content-Type':       'application/json',
    'Content-Length':     Buffer.byteLength(rawBody).toString(),
    'User-Agent':         USER_AGENT,
    'X-QODIQA-Event':     eventType,
    'X-QODIQA-Event-ID':  eventId,
    'X-QODIQA-Timestamp': timestamp,
    'X-QODIQA-Signature': signature,
  };

  const secureLookup = createSecureLookup(hostname, addressSetKey, cfg);
  const tlsOpts      = buildTlsOptions(cfg);

  const reqOptions = {
    hostname: parsedUrl.hostname,
    port:     parsedUrl.port || 443,
    path:     parsedUrl.pathname + (parsedUrl.search ?? ''),
    method:   'POST',
    headers,
    lookup:   secureLookup,
    // TLS enforcement
    ...tlsOpts,
    // Connect + TLS combined timeout (fires the 'timeout' event)
    timeout:  cfg.connectTimeoutMs,
  };

  const startMs = Date.now();

  const result = await new Promise((resolve) => {
    // Total-request hard deadline
    const totalTimer = setTimeout(() => {
      req.destroy(new Error(`Total timeout after ${cfg.totalTimeoutMs}ms`));
    }, cfg.totalTimeoutMs);

    const req = https.request(reqOptions, (res) => {
      // Arm response-headers timeout (we already have headers here, but
      // guard against response body taking too long to drain)
      const bodyTimer = setTimeout(() => {
        res.destroy(new Error(`Response body timeout after ${cfg.responseBodyTimeoutMs}ms`));
      }, cfg.responseBodyTimeoutMs);

      res.resume(); // drain body to free socket
      res.on('end', () => {
        clearTimeout(totalTimer);
        clearTimeout(bodyTimer);
        const durationMs = Date.now() - startMs;
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        resolve({
          ok,
          httpStatus: res.statusCode,
          durationMs,
          error: ok ? null : `HTTP ${res.statusCode}`,
        });
      });
      res.on('error', (err) => {
        clearTimeout(totalTimer);
        clearTimeout(bodyTimer);
        resolve({
          ok:         false,
          httpStatus: null,
          durationMs: Date.now() - startMs,
          error:      err.message,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      clearTimeout(totalTimer);
      resolve({
        ok:         false,
        httpStatus: null,
        durationMs: Date.now() - startMs,
        error:      `Connection timeout after ${cfg.connectTimeoutMs}ms`,
      });
    });

    req.on('error', (err) => {
      clearTimeout(totalTimer);
      resolve({
        ok:         false,
        httpStatus: null,
        durationMs: Date.now() - startMs,
        error:      err.message,
      });
    });

    req.write(rawBody);
    req.end();
  });

  // ── 4. Circuit breaker outcome ───────────────────────────────────────────────

  if (result.ok) {
    cb.onSuccess();
  } else {
    cb.onFailure();
  }

  return result;
}

// ── Delivery orchestration ────────────────────────────────────────────────────

/**
 * Deliver a webhook event to a single endpoint.
 * Logs the attempt and updates metrics.
 * Called by both the dispatcher (attempt 1) and the retry handler (attempts 2+).
 *
 * @param {object} opts
 * @param {string} opts.endpointId
 * @param {string} opts.url
 * @param {string} opts.secret      plaintext secret
 * @param {string} opts.eventId
 * @param {string} opts.eventType
 * @param {object} opts.payload
 * @param {number} opts.attempt
 * @param {object} [opts.config]    optional security config override
 * @returns {Promise<{ ok: boolean, httpStatus: number|null, durationMs: number, error: string|null }>}
 */
async function deliver({ endpointId, url, secret, eventId, eventType, payload, attempt, config }) {
  const result = await post({ url, secret, eventId, eventType, payload, config });

  // Log the attempt (non-fatal if PG is down)
  await logDelivery({
    endpointId,
    eventId,
    eventType,
    attempt,
    httpStatus: result.httpStatus,
    durationMs: result.durationMs,
    success:    result.ok,
    errorMsg:   result.error,
  });

  if (result.ok) {
    metrics.inc('webhook_deliveries_total',          { eventType });
    metrics.add('webhook_delivery_latency_ms', result.durationMs, { eventType });
    promMetrics.webhookDeliveriesTotal.inc({ event_type: eventType });
    promMetrics.webhookDeliveryDurationMs.observe({ event_type: eventType }, result.durationMs);
    emit('INFO', 'WEBHOOK_DELIVERY_SENT', {
      endpointId,
      eventId,
      eventType,
      attempt,
      httpStatus:  result.httpStatus,
      durationMs:  result.durationMs,
    });
  } else {
    metrics.inc('webhook_delivery_failures_total', { eventType });
    promMetrics.webhookDeliveryFailuresTotal.inc({ event_type: eventType });
    emit('WARN', 'WEBHOOK_DELIVERY_FAILED', {
      endpointId,
      eventId,
      eventType,
      attempt,
      httpStatus: result.httpStatus,
      durationMs: result.durationMs,
      error:      result.error,
    });
  }

  return result;
}

/**
 * Delivery retry handler — called by the persistence recovery worker.
 * Looks up the endpoint from PG (to get the decrypted secret) and attempts
 * delivery, then applies the safe retry policy to decide whether another
 * attempt should be scheduled.
 *
 * Safe retry policy enforcement (Component 44.6):
 *   • POSTs are not retried unless the operation payload has isIdempotent = true.
 *   • Permanent HTTP failures (4xx except 408/409/429) stop retrying immediately.
 *   • Attempt count is capped at config.maxRetryAttempts independently of the
 *     persistence recovery queue's own MAX_RETRIES.
 *
 * @param {object}  operation
 * @param {object}  operation.payload
 * @param {string}  operation.payload.endpointId
 * @param {string}  operation.payload.eventId
 * @param {string}  operation.payload.eventType
 * @param {object}  operation.payload.eventPayload
 * @param {boolean} [operation.payload.isIdempotent]  Must be true to allow retries
 * @param {string}  [operation.payload.httpMethod]    HTTP method (default: 'POST')
 * @param {number}  operation.retryCount  0-based; attempt = retryCount + 1
 * @returns {Promise<{ success: boolean, error?: string }>}
 */
async function retryHandler(operation) {
  const {
    endpointId,
    eventId,
    eventType,
    eventPayload,
    isIdempotent = false,
    httpMethod   = 'POST',
  } = operation.payload;

  const attempt = (operation.retryCount ?? 0) + 1;
  const cfg     = defaultConfig;

  if (attempt > 1) {
    metrics.inc('webhook_retries_total', { eventType });
    promMetrics.webhookRetriesTotal.inc({ event_type: eventType });
  }

  // Tenant context for this delivery is recovered from the event payload the
  // dispatcher enqueued (buildCertificationCompletedPayload/
  // buildAttestationCompletedPayload already embed tenantId there) — this
  // background path has no HTTP request to draw it from. No implicit/default
  // tenant: a missing or malformed tenantId fails closed exactly like an
  // endpoint that no longer exists, rather than querying without context.
  const tenantId = eventPayload?.tenantId ?? null;

  let endpoint;
  try {
    endpoint = tenantId ? await store._getEndpointForDelivery(endpointId, tenantId) : null;
  } catch (err) {
    emit('WARN', 'WEBHOOK_DELIVERY_TENANT_CONTEXT_FAILED', {
      endpointId, eventId, eventType, error: err.message,
    });
    return { success: true }; // fail-closed: cannot establish tenant context, do not retry indefinitely
  }

  // Look up endpoint — if not found, disabled, or tenant context unavailable, stop retrying
  if (!endpoint) {
    emit('WARN', 'WEBHOOK_DELIVERY_ENDPOINT_GONE', { endpointId, eventId, eventType });
    return { success: true }; // treat as success to avoid endless retries
  }

  const result = await deliver({
    endpointId,
    url:       endpoint.url,
    secret:    endpoint._secret,
    eventId,
    eventType,
    payload:   eventPayload,
    attempt,
  });

  if (result.ok) return { success: true };

  // ── Safe retry policy ───────────────────────────────────────────────────────

  const policy = shouldRetry({
    isIdempotent,
    httpMethod,
    attempt,
    maxAttempts: cfg.maxRetryAttempts,
    httpStatus:  result.httpStatus,
  });

  if (!policy.retry) {
    emit('INFO', 'WEBHOOK_RETRY_SUPPRESSED', {
      endpointId,
      eventId,
      eventType,
      attempt,
      httpStatus:  result.httpStatus,
      isIdempotent,
      reason:      policy.reason,
    });
    // (D6): no further attempt is scheduled, but the event was NOT
    // delivered — it goes to the Dead Letter Queue (as this component's
    // dispatcher documents), where it is visible (qodiqa_prq_dlq_depth,
    // QUEUE_BACKLOG alert) and replayable. Returning success here used to mark
    // the operation complete, so with the default caps (5 webhook attempts,
    // 5 queue retries) an undeliverable event could never reach the DLQ and
    // silently vanished. The "non-retryable:" prefix makes the worker move it
    // to the DLQ at once (worker.js).
    return { success: false, error: `non-retryable: webhook delivery abandoned — ${policy.reason}` };
  }

  emit('INFO', 'WEBHOOK_RETRY_SCHEDULED', {
    endpointId,
    eventId,
    eventType,
    attempt,
    httpStatus: result.httpStatus,
    reason:     policy.reason,
  });

  return { success: false, error: result.error ?? 'delivery failed' };
}

module.exports = { deliver, retryHandler, validateUrl, computeSignature, post };
