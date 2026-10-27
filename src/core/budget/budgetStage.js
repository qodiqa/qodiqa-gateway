'use strict';

/**
 * The budget stage of the request pipeline. Enforces the BUDGET rules (services/policy/evaluators/budget.js) of the tenant's policy set:
 *
 *   reserve(ctx)   after every other rule has passed and just before the provider is called: checks the per-request limits and charges the period counters ATOMICALLY with an upper
 *                  ESTIMATE of the request (1 request, the estimated tokens, the estimated cost). If any counter would exceed its limit nothing stays charged (every earlier charge of
 *                  this call is refunded) and the request is refused.
 *   settle(r, u)   after the provider answered: replaces the estimate by the real usage (tokens and cost) and returns the cost accounting of the request.
 *   refund(r)      the provider failed: the whole reservation is returned.
 *
 * Counters live in the policy store (memory or Redis, atomic Lua scripts). If the store fails the request is refused (BUDGET_UNAVAILABLE): a budget that cannot be counted is not
 * a budget that can be skipped. A rule applies to a request only if it lists the model (or lists none).
 *
 * Money: costMicros are millionths of the rule's currency, rounded UP per request. The estimate is an upper bound (prompt tokens at the input price plus `assumedOutputTokens` at
 * the output price); settle() corrects it with the provider's reported usage (inputTokens / outputTokens), and falls back to keeping the estimate when no usage is reported.
 */

const { emit } = require('../../../services/logger');

const budgetPolicies = (policies) => (policies || []).filter((p) => p && p.type === 'BUDGET' && p.enabled === true && p.config)
  .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0) || String(a.id).localeCompare(String(b.id)));

const applies = (cfg, model) => !cfg.models || (typeof model === 'string' && cfg.models.includes(model));
const rateFor = (pricing, model) => (pricing && pricing.byModel && model && Object.prototype.hasOwnProperty.call(pricing.byModel, model) ? pricing.byModel[model] : pricing);
const ceilDiv = (a, b) => Math.ceil(a / b);

function costMicros(pricing, model, inputTokens, outputTokens) {
  if (!pricing) return 0;
  const r = rateFor(pricing, model);
  return ceilDiv(inputTokens * r.inputPerMillionMicros + outputTokens * r.outputPerMillionMicros, 1_000_000);
}

function keyFor(policy, metric, ctx) {
  const who = policy.config.scope === 'tenant' ? (ctx.tenantId || 'none') : (ctx.callerId || ctx.userId || 'anonymous');
  // F8V-12: the period index is part of the key, so a refund or settlement made after the period rolled over adjusts the period that was charged, never the new one
  if (!(policy.config._periodSeconds > 0)) throw new Error('BUDGET rule was not preprocessed');          // gate A-03: never a silent one-second window
  const period = Math.floor(Date.now() / 1000 / policy.config._periodSeconds);
  return `budget:${policy.id}:${policy.config.scope}:${who}:${metric}:${period}`;
}

/** The smallest latency limit of the rules that apply, or null. */
function latencyLimitMs(policies, model) {
  let ms = null;
  for (const p of budgetPolicies(policies)) if (applies(p.config, model) && p.config.perRequest && p.config.perRequest.maxLatencyMs) ms = ms === null ? p.config.perRequest.maxLatencyMs : Math.min(ms, p.config.perRequest.maxLatencyMs);
  return ms;
}

/**
 * @param {{ policies: object[], store: object, tenantId: string|null, callerId?: string|null, userId?: string|null, model?: string|null, estimatedTokens: number }} ctx
 * @returns {Promise<{ allowed: true, reservation: object|null } | { allowed: false, reason: string, policyId: string }>}
 */
async function reserve(ctx) {
  const rules = budgetPolicies(ctx.policies).filter((p) => applies(p.config, ctx.model));
  if (rules.length === 0) return { allowed: true, reservation: null };
  const store = ctx.store;
  const est = Math.max(0, Math.ceil(ctx.estimatedTokens || 0));
  const charges = [];
  const undo = async () => { for (const c of charges.splice(0).reverse()) { try { await store.adjust(c.key, c.window, -c.amount); } catch (e) { emit('ERROR', 'BUDGET_REFUND_FAILED', { key: c.key, error: e.message }); } } };
  const deny = async (reason, policy) => { await undo(); return { allowed: false, reason, policyId: policy.id }; };
  try {
    for (const p of rules) {
      const c = p.config; const window = c._periodSeconds; const lim = c.limits || {}; const per = c.perRequest || {};
      const estCost = c.pricing ? costMicros(c.pricing, ctx.model, est, c.pricing.assumedOutputTokens || 1000) : 0;
      if (per.maxTokens !== undefined && est > per.maxTokens) return deny('BUDGET_REQUEST_TOO_LARGE', p);
      if (per.maxCostMicros !== undefined && estCost > per.maxCostMicros) return deny('BUDGET_REQUEST_TOO_COSTLY', p);
      const todo = [['requests', 1, lim.requests], ['tokens', est, lim.tokens], ['cost', estCost, lim.costMicros]].filter(([, , max]) => max !== undefined);
      for (const [metric, amount, max] of todo) {
        const key = keyFor(p, metric, ctx);
        if (amount > max) return deny(`BUDGET_EXCEEDED_${metric.toUpperCase()}`, p);
        const r = await store.chargeBy(key, window, amount, max);
        if (!r.allowed) return deny(`BUDGET_EXCEEDED_${metric.toUpperCase()}`, p);
        charges.push({ key, window, amount, metric, policyId: p.id });
      }
    }
  } catch (e) {
    await undo();
    emit('ERROR', 'BUDGET_STORE_ERROR', { error: e && e.message });
    return { allowed: false, reason: 'BUDGET_UNAVAILABLE', policyId: rules[0].id };
  }
  return { allowed: true, reservation: { charges, estimatedTokens: est, model: ctx.model || null, tenantId: ctx.tenantId || null, store, rules: rules.map((p) => ({ id: p.id, pricing: p.config.pricing || null })) } };
}

/** @returns {Promise<{ inputTokens: number|null, outputTokens: number|null, costMicros: number, currency: string|null }>} the accounting of the request */
async function settle(reservation, usage) {
  if (!reservation) return null;
  const { store, charges, estimatedTokens, model } = reservation;
  const u = usage || {};
  const inT = Number.isFinite(u.inputTokens) ? u.inputTokens : null;
  const outT = Number.isFinite(u.outputTokens) ? u.outputTokens : null;
  const haveReal = inT !== null && outT !== null;
  const actualTokens = haveReal ? inT + outT : estimatedTokens;
  let accounted = { inputTokens: inT, outputTokens: outT, costMicros: 0, currency: null };
  for (const c of charges) {
    try {
      if (c.metric === 'tokens' && haveReal && actualTokens !== c.amount) await store.adjust(c.key, c.window, actualTokens - c.amount);
      if (c.metric === 'cost') {
        const rule = reservation.rules.find((r) => r.id === c.policyId);
        const real = haveReal ? costMicros(rule.pricing, model, inT, outT) : c.amount;
        if (real !== c.amount) await store.adjust(c.key, c.window, real - c.amount);
        accounted = { ...accounted, costMicros: real, currency: rule.pricing.currency };
      }
    } catch (e) { emit('ERROR', 'BUDGET_SETTLE_FAILED', { key: c.key, error: e.message }); }
  }
  if (accounted.currency === null) { const priced = reservation.rules.find((r) => r.pricing); if (priced && haveReal) accounted = { ...accounted, costMicros: costMicros(priced.pricing, model, inT, outT), currency: priced.pricing.currency }; }
  emit('INFO', 'COST_ACCOUNTED', { tenantId: reservation.tenantId, model, inputTokens: inT, outputTokens: outT, estimated: !haveReal, costMicros: accounted.costMicros, currency: accounted.currency });
  return accounted;
}

async function refund(reservation) {
  if (!reservation) return;
  for (const c of reservation.charges.slice().reverse()) { try { await reservation.store.adjust(c.key, c.window, -c.amount); } catch (e) { emit('ERROR', 'BUDGET_REFUND_FAILED', { key: c.key, error: e.message }); } }
}

/** Current consumption of every applicable counter, for a report. */
async function status(policies, ctx) {
  const out = [];
  for (const p of budgetPolicies(policies)) {
    const lim = p.config.limits || {};
    for (const [metric, max] of [['requests', lim.requests], ['tokens', lim.tokens], ['cost', lim.costMicros]]) {
      if (max === undefined) continue;
      out.push({ policyId: p.id, scope: p.config.scope, period: p.config.period, metric, limit: max, used: await ctx.store.getCount(keyFor(p, metric, ctx), p.config._periodSeconds) });
    }
  }
  return out;
}

module.exports = { reserve, settle, refund, status, latencyLimitMs, budgetPolicies, costMicros, keyFor };
