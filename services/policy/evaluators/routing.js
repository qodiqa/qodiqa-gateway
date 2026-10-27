'use strict';

/**
 * ROUTING policy rule: which provider (and model) serves a request, chosen by policy from an operator-listed set of candidates by cost, latency or load.
 * Like DLP, BUDGET and CONTENT_RULE it does not decide on the request context: it is the governed, hashed statement of the routing, applied by src/core/routing/routingStage.js
 * when a request is about to be dispatched. As an evaluator it always passes.
 *
 *   {
 *     routingFormat: 1,
 *     strategy:  'ordered' | 'cheapest' | 'fastest' | 'least-loaded',
 *     candidates: [ { provider: 'openai', model?: 'gpt-4o-mini' }, ... ]       1..16 providers (built-in or compat-<id>), tried in the order the strategy gives
 *     modelMode: 'fill' | 'override',          fill (default): the candidate's `model` is used only when the request named none; override: it always replaces the request's model
 *     when:      <ABAC condition>,             optional: the rule applies only to requests for which it is true (attributes.js; request.provider = the provider the artifact names)
 *     pricing:   { '<provider>': { currency, inputPerMillionMicros, outputPerMillionMicros, byModel? } }    used by `cheapest` (a candidate with no price sorts last)
 *   }
 *
 * What routing can and cannot do (the guarantees the stage enforces, not this file):
 *   - The signed artifact still names a provider. Routing may send the request elsewhere ONLY to a candidate that the same caller is authorised for NOW - the failover
 *     authorisation: signing identity enabled with SIGN_ARTIFACT, the identity's provider scope, consent and the effective policies (residency, data-class limits, ABAC) evaluated FOR
 *     THE CANDIDATE. A candidate that fails is skipped; if none passes, the artifact's own provider is used; if that is not a candidate it is still the fallback.
 *   - Every routed request records requested vs executing provider, the rule, the strategy and any model replacement in the audit entry (executionContext.routed).
 */

const condition = require('../abac/condition');

const FORMAT = 1;
const STRATEGIES = Object.freeze(['ordered', 'cheapest', 'fastest', 'least-loaded']);
const PROVIDER_RE = /^[a-z][a-z0-9-]{1,40}$/;
const ALLOWED = new Set(['routingFormat', 'strategy', 'candidates', 'modelMode', 'when', 'pricing']);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const MODEL_OK = (m) => typeof m === 'string' && m.length > 0 && m.length <= 128 && m.trim() === m && !/[\u0000-\u001f\u007f]/.test(m);

function validatePrice(p, where) {
  if (!isObj(p)) throw new Error(`${where}: a price is an object`);
  const allowed = new Set(['currency', 'inputPerMillionMicros', 'outputPerMillionMicros', 'byModel']);
  for (const k of Object.keys(p)) if (!allowed.has(k)) throw new Error(`${where}: unknown price member ${k}`);
  if (typeof p.currency !== 'string' || !/^[A-Z]{3}$/.test(p.currency)) throw new Error(`${where}: currency is an ISO 4217 code`);
  for (const k of ['inputPerMillionMicros', 'outputPerMillionMicros']) if (!Number.isInteger(p[k]) || p[k] < 0 || p[k] > 1e12) throw new Error(`${where}: ${k} is a non-negative integer`);
  if (p.byModel !== undefined) {
    if (!isObj(p.byModel) || Object.keys(p.byModel).length > 100) throw new Error(`${where}: byModel is an object of at most 100 models`);
    for (const [m, v] of Object.entries(p.byModel)) {
      if (!MODEL_OK(m) || ['__proto__', 'constructor', 'prototype'].includes(m)) throw new Error(`${where}: invalid model id in byModel`);
      if (v && v.currency !== undefined && v.currency !== p.currency) throw new Error(`${where}.byModel: a model price uses its provider's currency (${p.currency})`);   // F9R-01
      validatePrice({ currency: p.currency, ...v }, `${where}.byModel`);
    }
  }
}

function validate(config) {
  for (const k of Object.keys(config)) if (!ALLOWED.has(k)) throw new Error(`unknown ROUTING config key: ${k}`);
  if (config.routingFormat !== FORMAT) throw new Error(`config.routingFormat must be ${FORMAT}`);
  if (!STRATEGIES.includes(config.strategy)) throw new Error(`config.strategy must be one of ${STRATEGIES.join(', ')}`);
  if (!Array.isArray(config.candidates) || config.candidates.length < 1 || config.candidates.length > 16) throw new Error('config.candidates must list 1..16 providers');
  const seen = new Set();
  for (const c of config.candidates) {
    if (!isObj(c) || Object.keys(c).some((k) => !['provider', 'model'].includes(k))) throw new Error('a candidate is { provider, model? }');
    if (typeof c.provider !== 'string' || !PROVIDER_RE.test(c.provider)) throw new Error(`invalid candidate provider: ${String(c.provider).slice(0, 40)}`);
    if (seen.has(c.provider)) throw new Error(`candidate provider listed twice: ${c.provider}`);
    seen.add(c.provider);
    if (c.model !== undefined && !MODEL_OK(c.model)) throw new Error(`candidate ${c.provider}: model is a model id`);
  }
  if (config.modelMode !== undefined && !['fill', 'override'].includes(config.modelMode)) throw new Error('config.modelMode is fill or override');
  if (config.when !== undefined) condition.validate(config.when);
  if (config.pricing !== undefined) {
    if (!isObj(config.pricing) || Object.keys(config.pricing).length > 32) throw new Error('config.pricing is an object of at most 32 providers');
    for (const [p, price] of Object.entries(config.pricing)) {
      if (!PROVIDER_RE.test(p)) throw new Error(`invalid pricing provider: ${p.slice(0, 40)}`);
      validatePrice(price, `pricing.${p}`);
    }
  }
  if (config.strategy === 'cheapest' && !config.pricing) throw new Error('strategy "cheapest" needs config.pricing');
  if (config.pricing && new Set(Object.values(config.pricing).map((p) => p.currency)).size > 1) throw new Error('config.pricing must use one currency (costs in different currencies are not comparable)');
}

function preprocess(config) {
  return { ...config, _when: config.when ? condition.prepare(config.when) : null };
}

function evaluate() { return { pass: true }; }

module.exports = { validate, preprocess, evaluate, FORMAT, STRATEGIES };
