'use strict';

/**
 * classification length cap + per-tenant classification budget.
 *
 * Semantic cost scales with input: p95 153 ms at 4k characters, 1.16 s at 32k (audit). Truncating would leave
 * text unclassified — a bypass — so it is never done. Instead:
 *
 *   • INPUT: the request prompt is already capped at MAX_PROMPT_BYTES = 32,768 (400 PROMPT_TOO_LARGE, pre-auth,
 *     src/validation/schemas/aiChat.schema.js). Unchanged.
 *   • OUTPUT: provider output beyond OUTPUT_MAX_CHARS (default 65,536) is BLOCKed OUTPUT_TOO_LARGE — withheld on the
 *     non-stream path, cancelled at the point the cap is crossed on a stream (nothing past it is released). Never
 *     truncated-and-released.
 *   • BUDGET: each tenant has a token bucket of classification WINDOWS (the classifier's own 400-char windows; one
 *     window ≈ one embedding). REQUEST side: charged BEFORE classification — when the bucket cannot cover the
 *     prompt's windows the request is refused 429 CLASSIFICATION_BUDGET_EXHAUSTED + Retry-After (a throttle, like
 *'s RATE_LIMITED: not an enforcement decision, no audit entry, no provider call). OUTPUT side: charged AFTER
 *     classification and NEVER refused or skipped — it may take the bucket into bounded debt (down to −burst), which
 *     throttles the tenant's NEXT requests.
 *
 * Consequence (asserted by tests): every accepted request's text is classified in full, and every released output
 * character has passed classification. The budget is per process (one instance); multi-replica fairness is.
 */

function _int(name, dflt, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return dflt;
  const v = Number(raw);
  return Number.isInteger(v) && v >= min && v <= max ? v : dflt; // boot rule perf.admission refuses bad values
}

const OUTPUT_MAX_CHARS  = _int('QODIQA_OUTPUT_CLASSIFY_MAX_CHARS', 65_536, 1_000, 10_000_000);
const REFILL_PER_SEC    = _int('QODIQA_CLASSIFY_BUDGET_REFILL_PER_SEC', 2_000, 1, 10_000_000);
const BURST             = _int('QODIQA_CLASSIFY_BUDGET_BURST', 20_000, 1, 100_000_000);
const MAX_TENANTS       = 100_000; // bounded state; the least-recently-seen tenant bucket is dropped (refills to full)

const WINDOW = 400; const STRIDE = 350;
/** Windows the classifier cuts from a text of this length (stride formula; tail-window dedupe ignored: ≤ +1). */
function windowsForLength(len) {
  if (!Number.isFinite(len) || len <= WINDOW) return 1;
  return Math.ceil((len - WINDOW) / STRIDE) + 1;
}

// step 7: refill is measured on the monotonic clock. On the
// wall clock a backward step of Δ made the elapsed time negative and DRAINED Δ × refill tokens with no floor — the
// fault suite measured a 120 s step blocking every request 429 for the whole 120 s. Elapsed is also floored at 0.
const { monoNowMs } = require('../../infra/time/monotonicClock');

function createBudget({ refillPerSec = REFILL_PER_SEC, burst = BURST, now = () => monoNowMs(), maxTenants = MAX_TENANTS } = {}) {
  const buckets = new Map(); // tenant -> { tokens, at }
  const bucket = (tenant) => {
    const k = tenant || '__none__';
    let b = buckets.get(k);
    const t = now();
    if (!b) { b = { tokens: burst, at: t }; }
    else { b.tokens = Math.min(burst, b.tokens + (Math.max(0, t - b.at) / 1000) * refillPerSec); b.at = t; buckets.delete(k); }
    buckets.set(k, b); // most-recently-seen last
    while (buckets.size > maxTenants) buckets.delete(buckets.keys().next().value);
    return b;
  };
  return {
    /** Request side: take `n` windows or refuse. */
    take(tenant, n) {
      const b = bucket(tenant);
      if (b.tokens >= n) { b.tokens -= n; return { ok: true, remaining: b.tokens }; }
      return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((n - b.tokens) / refillPerSec)), remaining: b.tokens };
    },
    /** Output side: always charged, never refused; bounded debt. */
    charge(tenant, n) {
      const b = bucket(tenant);
      b.tokens = Math.max(-burst, b.tokens - n);
      return { remaining: b.tokens };
    },
    peek(tenant) { return bucket(tenant).tokens; },
    config: { refillPerSec, burst, maxTenants },
  };
}

const _default = createBudget();

module.exports = { OUTPUT_MAX_CHARS, REFILL_PER_SEC, BURST, windowsForLength, createBudget, take: _default.take, charge: _default.charge, peek: _default.peek };
