'use strict';

/**
 * Provider cost accounting and comparison.
 *
 * Tariffs. A tariff is the operator's price for a provider (and optionally per model): `{ currency, inputPerMillionMicros, outputPerMillionMicros, byModel? }` (millionths of the
 * currency per million tokens), carried by the ROUTING rule's `pricing` (and by a BUDGET rule's `pricing`, which accounts the same way). The platform ships no price list: prices
 * change, so they are policy data, versioned and hashed like any rule.
 *
 *   account({ policies, provider, model, tokenUsage }) -> { costMicros, currency } | null
 *       cost of ONE finished call from the tokens the provider reported, using the first enabled ROUTING rule (priority, then id) that prices the provider; counted in
 *       qodiqa_provider_cost_micros_total / qodiqa_provider_tokens_total. Null when no tariff covers the provider or the provider reported no usage (nothing is invented).
 *
 *   compare({ policies, providers?, inputTokens, outputTokens, weights?, health? }) -> { providers: [...], ranked: [...] }
 *       for each enabled provider (or the listed ones): estimated cost of a request of that size, recent average latency / failure rate / degraded flag (providerHealth), calls in
 *       flight, and a weighted score. `weights` { cost, latency, failure } (non-negative numbers, default 1/1/1) are applied to each metric normalised to 0..1 across the
 *       compared providers (lowest is best); a provider with no price or no latency sample scores the WORST value for that metric (unknown is not a bargain). `ranked` is the
 *       provider names, best first.
 */

const { costMicros } = require('../budget/budgetStage');
const { getProviderConfig } = require('../../../services/providers/config');
const providerHealth = require('../../../services/providers/providerHealth');
const providerLoad = require('../../../services/providers/providerLoad');
const routingStage = require('../routing/routingStage');

function _metrics() { try { return require('../../observability/metrics'); } catch { return null; } }

/** The tariff of a provider from the effective policy set, or null. */
function tariffFor(policies, provider) {
  for (const p of routingStage.rules(policies)) {
    const pricing = p.config.pricing;
    if (pricing && Object.prototype.hasOwnProperty.call(pricing, provider)) return { ruleId: p.id, price: pricing[provider] };
  }
  return null;
}

function account({ policies, provider, model, tokenUsage }) {
  const inT = tokenUsage && Number.isFinite(tokenUsage.inputTokens) ? tokenUsage.inputTokens : null;
  const outT = tokenUsage && Number.isFinite(tokenUsage.outputTokens) ? tokenUsage.outputTokens : null;
  const m = _metrics();
  if (m && m.providerTokensTotal) { if (inT !== null) m.providerTokensTotal.inc({ provider, direction: 'input' }, inT); if (outT !== null) m.providerTokensTotal.inc({ provider, direction: 'output' }, outT); }
  const t = tariffFor(policies, provider);
  if (!t || inT === null || outT === null) return null;
  const cost = costMicros(t.price, model, inT, outT);
  if (m && m.providerCostMicrosTotal) m.providerCostMicrosTotal.inc({ provider, currency: t.price.currency }, cost);
  return { costMicros: cost, currency: t.price.currency, ruleId: t.ruleId };
}

const norm = (values) => {
  const finite = values.filter(Number.isFinite);
  if (finite.length === 0) return values.map(() => 1);
  const lo = Math.min(...finite); const hi = Math.max(...finite);
  return values.map((v) => (!Number.isFinite(v) ? 1 : (hi === lo ? 0 : (v - lo) / (hi - lo))));
};

function compare({ policies, providers, inputTokens, outputTokens, weights = {}, names }) {
  const w = { cost: 1, latency: 1, failure: 1, ...weights };
  for (const k of Object.keys(w)) if (!(Number.isFinite(w[k]) && w[k] >= 0)) throw new RangeError(`weight ${k} must be a non-negative number`);
  const list = (providers && providers.length ? providers : names).filter((n) => { const c = getProviderConfig(n); return c && c.enabled; });
  const rows = list.map((name) => {
    const t = tariffFor(policies, name);
    const cfg = getProviderConfig(name);
    const model = cfg && cfg.defaultModel ? cfg.defaultModel : null;
    const h = providerHealth.snapshot(name);
    return { provider: name, tariff: t ? { ruleId: t.ruleId, currency: t.price.currency } : null,
      estimatedCostMicros: t ? costMicros(t.price, model, inputTokens, outputTokens) : null, currency: t ? t.price.currency : null,
      avgLatencyMs: h.successSamples > 0 ? Math.round(h.successLatencyMs) : null, samples: h.samples, failureRate: h.samples > 0 ? h.failureRate : null, degraded: providerHealth.isDegraded(name), inFlight: providerLoad.get(name) };
  });
  const c = norm(rows.map((r) => (r.estimatedCostMicros === null ? NaN : r.estimatedCostMicros)));
  const l = norm(rows.map((r) => (r.avgLatencyMs === null ? NaN : r.avgLatencyMs)));
  const f = norm(rows.map((r) => (r.failureRate === null ? NaN : r.failureRate)));
  rows.forEach((r, i) => { r.score = Number((w.cost * c[i] + w.latency * l[i] + w.failure * f[i]).toFixed(6)); });
  const ranked = [...rows].sort((a, b) => (a.degraded - b.degraded) || (a.score - b.score) || a.provider.localeCompare(b.provider)).map((r) => r.provider);
  return { providers: rows, ranked, weights: w, mixedCurrencies: new Set(rows.map((r) => r.currency).filter(Boolean)).size > 1 };
}

module.exports = { account, compare, tariffFor };
