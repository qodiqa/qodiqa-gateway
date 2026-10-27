'use strict';

/**
 * Policy routing stage: applies the ROUTING rules (services/policy/evaluators/routing.js) of the effective policy set to ONE request just before dispatch.
 *
 *   resolve({ policies, requestedProvider, body, attributes, context, authorize, estimatedTokens }) ->
 *     { provider, model, routed }      provider/model to dispatch to; `model` is undefined when the request's own model stands
 *                                      routed = null (nothing applied) | { ruleId, strategy, from, to, modelFrom, modelTo, order: [..], skipped: [{ provider, reason }] }
 *
 * The first enabled ROUTING rule (priority, then id) whose `when` is true for the request decides the candidate set and strategy:
 *   ordered        as listed
 *   cheapest       by estimated cost of this request (tariff in the rule's pricing; a candidate with no price sorts last)
 *   fastest        by the recent average latency recorded for the provider (providerHealth); providers with no samples sort after measured ones
 *   least-loaded   by calls in flight on this process (providerLoad)
 * Degraded providers (providerHealth.isDegraded) are tried after healthy ones. A candidate other than the artifact's own provider is used ONLY if `authorize(candidate)` says
 * the same caller may use it now (the failover authorisation: identity scope, consent, effective policies evaluated for the candidate - so residency, data-class and ABAC rules apply
 * to the routed target exactly as to the requested one), it is enabled, and the model that would be sent is allowed there. The artifact's own provider is always the final fallback.
 */

const { evaluate: evalCondition } = require('../../../services/policy/abac/condition');
const { getProviderConfig, resolveDefaultModel } = require('../../../services/providers/config');
const { validateModelAgainstConfig } = require('../../../services/providers/modelValidation');
const providerHealth = require('../../../services/providers/providerHealth');
const providerLoad = require('../../../services/providers/providerLoad');
const { costMicros } = require('../budget/budgetStage');
const { emit } = require('../../../services/logger');

const ASSUMED_OUTPUT_TOKENS = 500;

const rules = (policies) => (policies || []).filter((p) => p && p.type === 'ROUTING' && p.enabled === true && p.config)
  .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0) || String(a.id).localeCompare(String(b.id)));

function applies(p, ctx) {
  if (!p.config._when) return true;
  try { return evalCondition(p.config._when, ctx) === true; } catch { return false; }       // an unreadable condition never routes
}

function priceOf(cfg, provider, model, inTok) {
  const price = cfg.pricing && Object.prototype.hasOwnProperty.call(cfg.pricing, provider) ? cfg.pricing[provider] : null;
  if (!price) return Infinity;
  return costMicros(price, model, inTok, ASSUMED_OUTPUT_TOKENS);
}

function order(cfg, candidates, { model, inTok }) {
  const idx = new Map(candidates.map((c, i) => [c.provider, i]));
  const key = (c) => {
    switch (cfg.strategy) {
      case 'cheapest': return priceOf(cfg, c.provider, c.model || model, inTok);
      case 'fastest': { const s = providerHealth.snapshot(c.provider); return s.successSamples > 0 ? s.successLatencyMs : Infinity; }
      case 'least-loaded': return providerLoad.get(c.provider);
      default: return 0;
    }
  };
  const degraded = (c) => (providerHealth.isDegraded(c.provider) ? 1 : 0);
  return [...candidates].sort((a, b) => degraded(a) - degraded(b) || key(a) - key(b) || idx.get(a.provider) - idx.get(b.provider));
}

async function resolve({ policies, requestedProvider, body, attributes, context = {}, authorize, estimatedTokens = 0 }) {
  const none = { provider: requestedProvider, model: undefined, routed: null };
  const rule = rules(policies).find((p) => applies(p, { ...context, action: requestedProvider, attributes: attributes || {} }));
  if (!rule) return none;
  const cfg = rule.config;
  const requestModel = body && typeof body.model === 'string' && body.model ? body.model : null;
  const skipped = [];
  const sequence = order(cfg, cfg.candidates, { model: requestModel, inTok: estimatedTokens });

  for (const cand of sequence) {
    const conf = getProviderConfig(cand.provider);
    if (!conf || !conf.enabled) { skipped.push({ provider: cand.provider, reason: 'NOT_ENABLED' }); continue; }
    const override = cfg.modelMode === 'override';
    const model = (cand.model && (override || !requestModel)) ? cand.model : (requestModel || resolveDefaultModel(cand.provider));
    if (!model) { skipped.push({ provider: cand.provider, reason: 'NO_MODEL' }); continue; }
    if (!validateModelAgainstConfig(conf, model).ok) { skipped.push({ provider: cand.provider, reason: 'MODEL_NOT_ALLOWED' }); continue; }
    // a candidate other than the artifact's provider - or the same provider with a DIFFERENT model than the request would be served with - is judged by the authoriser (policies are model-aware)
    const servedModel = requestModel || resolveDefaultModel(requestedProvider);
    if (cand.provider !== requestedProvider || model !== servedModel) {
      let auth;
      try { auth = await authorize(cand.provider, { model }); } catch { auth = { ok: false, reason: 'AUTHORIZATION_ERROR' }; }
      if (!auth || auth.ok !== true) { skipped.push({ provider: cand.provider, reason: (auth && auth.reason) || 'NOT_AUTHORIZED' }); continue; }
    }
    const modelTo = model !== requestModel ? model : undefined;
    const routed = { ruleId: rule.id, strategy: cfg.strategy, from: requestedProvider, to: cand.provider, modelFrom: requestModel, modelTo: modelTo || requestModel,
      order: sequence.map((c) => c.provider), skipped };
    if (cand.provider !== requestedProvider || modelTo) emit('INFO', 'ROUTING_DECISION', { ruleId: rule.id, strategy: cfg.strategy, from: requestedProvider, to: cand.provider, modelReplaced: !!modelTo, skipped: skipped.length });
    return { provider: cand.provider, model: modelTo, routed };
  }
  emit('WARN', 'ROUTING_NO_CANDIDATE', { ruleId: rule.id, requestedProvider, skipped });
  return { ...none, routed: { ruleId: rule.id, strategy: cfg.strategy, from: requestedProvider, to: requestedProvider, modelFrom: requestModel, modelTo: requestModel, order: sequence.map((c) => c.provider), skipped, fallback: true } };
}

module.exports = { resolve, rules, order, ASSUMED_OUTPUT_TOKENS };
