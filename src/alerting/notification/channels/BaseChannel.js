'use strict';

/**
 * QODIQA Notification Channel — Abstract Base
 *
 * All notification channels extend this class.
 * Provides:
 *   - Exponential backoff retry with jitter
 *   - Per-channel rate limiting (token bucket)
 *   - Delivery tracking (success, failure, retry state)
 *   - Payload hash for audit trail
 */

const crypto = require('crypto');
const { emit } = require('../../../../services/logger');
const metrics = require('../../../observability/metrics');
const { monoNowMs } = require('../../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

class BaseChannel {
  /**
   * @param {object} opts
   * @param {string}  opts.name           — Channel identifier
   * @param {number}  [opts.maxRetries]   — Max delivery attempts (default 3)
   * @param {number}  [opts.baseDelayMs]  — Base delay for exponential backoff (default 1000ms)
   * @param {number}  [opts.maxDelayMs]   — Max delay cap (default 60 000ms)
   * @param {number}  [opts.rateLimit]    — Max sends per minute (default 60)
   */
  constructor({ name, maxRetries = 3, baseDelayMs = 1000, maxDelayMs = 60_000, rateLimit = 60 }) {
    this.name        = name;
    this.maxRetries  = maxRetries;
    this.baseDelayMs = baseDelayMs;
    this.maxDelayMs  = maxDelayMs;

    // Token bucket rate limiter
    this._rateCap    = rateLimit;
    this._tokens     = rateLimit;
    this._lastRefill = monoNowMs(); // monotonic (same-process)
    this._refillMs   = 60_000;  // replenish every 60s
  }

  // ── Abstract interface — subclasses must implement ─────────────────────────

  /**
   * Send a single notification.
   * @param {object} alert      — Alert payload
   * @param {string} recipient  — Destination (URL, email, Slack channel, etc.)
   * @param {object} [meta]     — Channel-specific metadata
   * @returns {Promise<{ ok: boolean, code?: number, message?: string }>}
   */
  // eslint-disable-next-line no-unused-vars
  async _send(alert, recipient, meta) {
    throw new Error(`${this.name}: _send() not implemented`);
  }

  /**
   * Format the alert into the channel-specific payload.
   * @returns {object}  — { body: string|object, contentType: string }
   */
  // eslint-disable-next-line no-unused-vars
  _format(alert) {
    return { body: JSON.stringify(alert), contentType: 'application/json' };
  }

  // ── Public delivery interface ──────────────────────────────────────────────

  /**
   * Deliver an alert with automatic retry and rate limiting.
   *
   * @param {object} alert
   * @param {string} recipient
   * @param {object} [meta]
   * @returns {Promise<{ sent: boolean, attempts: number, channel: string, error?: string }>}
   */
  async deliver(alert, recipient, meta = {}) {
    if (!this._consumeToken()) {
      emit('WARN', 'ALERT_CHANNEL_RATE_LIMITED', {
        channel: this.name, alertId: alert.id, recipient,
      });
      metrics.alertNotificationRateLimitedTotal.inc({ channel: this.name });
      return { sent: false, attempts: 0, channel: this.name, rateLimited: true };
    }

    let lastError = null;
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const result = await this._send(alert, recipient, meta);
        if (result.ok) {
          const { body } = this._format(alert);
          const payloadHash = crypto.createHash('sha256')
            .update(typeof body === 'string' ? body : JSON.stringify(body))
            .digest('hex');

          emit('INFO', 'ALERT_NOTIFICATION_SENT', {
            channel: this.name, alertId: alert.id, recipient,
            attempt, severity: alert.severity, type: alert.type,
          });
          metrics.alertNotificationSentTotal.inc({ channel: this.name, severity: alert.severity });
          return { sent: true, attempts: attempt, channel: this.name, payloadHash };
        }
        lastError = result.message ?? 'Unknown error';
      } catch (err) {
        lastError = err.message;
      }

      // Exponential backoff with ±25% jitter before retry
      if (attempt < this.maxRetries) {
        metrics.alertNotificationRetriesTotal.inc({ channel: this.name });
        const delay = Math.min(this.baseDelayMs * Math.pow(2, attempt - 1), this.maxDelayMs);
        const jitter = delay * 0.25 * (Math.random() * 2 - 1);
        await _sleep(Math.max(100, Math.round(delay + jitter)));
      }
    }

    emit('WARN', 'ALERT_NOTIFICATION_FAILED', {
      channel: this.name, alertId: alert.id, recipient,
      attempts: this.maxRetries, error: lastError,
    });
    metrics.alertNotificationFailedTotal.inc({ channel: this.name, severity: alert.severity });
    return { sent: false, attempts: this.maxRetries, channel: this.name, error: lastError };
  }

  /**
   * Health check — verify the channel is configured and reachable.
   * @returns {Promise<{ ok: boolean, latencyMs: number, error?: string }>}
   */
  async healthCheck() {
    return { ok: false, latencyMs: 0, error: `${this.name}: healthCheck() not implemented` };
  }

  // ── Token bucket rate limiter ──────────────────────────────────────────────

  _consumeToken() {
    const now = monoNowMs(); // monotonic (same-process)
    const elapsed = now - this._lastRefill;
    if (elapsed >= this._refillMs) {
      this._tokens    = this._rateCap;
      this._lastRefill = now;
    }

    if (this._tokens <= 0) return false;
    this._tokens--;
    return true;
  }
}

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { BaseChannel };
