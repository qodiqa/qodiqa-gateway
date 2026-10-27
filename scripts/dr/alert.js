'use strict';

/**
 * Best-effort failure alerting webhook (Slack/PagerDuty-compatible), shared
 * by the Node-based DR scripts (backup.js, cycle.js, verify.js) so failure
 * notification is consistent with scripts/pg-backup.sh's existing
 * `alert_failure()` — same `ALERT_WEBHOOK_URL` env var, same "never let the
 * alert call itself fail the job" contract.
 *
 * No-op if `url` is falsy (alerting is optional). Uses Node's built-in
 * `fetch` (available unconditionally on Node >= 18; this project requires
 * Node >= 22) — no new HTTP client dependency.
 *
 * the shipped Kubernetes Secret carries a
 * `REPLACE_WITH_…` placeholder for the optional alert-webhook-url, so the env
 * var is never actually unset and every alert was POSTed to a non-URL and
 * silently swallowed. A placeholder or non-http(s) value is now treated as
 * unset, and an ALERT_WEBHOOK_PLACEHOLDER line says so on stderr.
 */

function isUsableWebhook(url) {
  return typeof url === 'string' && !url.includes('REPLACE_WITH') && /^https?:\/\//.test(url);
}

async function postAlert(url, message) {
  if (!url) return;
  if (!isUsableWebhook(url)) {
    console.error(JSON.stringify({
      event: 'ALERT_WEBHOOK_PLACEHOLDER',
      message: 'ALERT_WEBHOOK_URL is a placeholder or not an http(s) URL — no alert was sent; set a real webhook or remove the key',
    }));
    return;
  }
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: `🚨 QODIQA DR alert: ${message}` }),
    });
  } catch {
    // Alerting must never throw into the caller's failure path — the
    // original failure (what we were trying to alert about) must still be
    // the thing that surfaces as the job's exit code.
  }
}

module.exports = { postAlert, isUsableWebhook };
