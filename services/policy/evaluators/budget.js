'use strict';

/**
 * BUDGET policy rule: quotas and budgets in requests, tokens and money, per tenant or per caller, over a period; limits on one request's size, cost and latency.
 * Like the DLP rule it does not decide on the request CONTEXT: it is the governed, hashed statement of the limits, enforced by the budget stage of the request pipeline
 * (src/core/budget/budgetStage.js), which charges the counters ATOMICALLY just before the provider is called - after every other rule has passed, so a request refused for another
 * reason never uses up a budget - and settles them with the real usage afterwards. As an evaluator it always passes.
 *
 *   {
 *     budgetFormat: 1,
 *     scope:   'tenant' | 'caller',
 *     period:  'minute' | 'hour' | 'day' | 'week' | 'month',      a ROLLING window that starts at the first charge and lasts the period (not a calendar boundary)
 *     models:  ['gpt-4o', ...],                                    optional: the rule applies only to these models
 *     limits:  { requests?: n, tokens?: n, costMicros?: n },       totals per period; costMicros are millionths of `pricing.currency`
 *     perRequest: { maxTokens?: n, maxCostMicros?: n, maxLatencyMs?: n },
 *     pricing: { currency: 'USD', inputPerMillionMicros: n, outputPerMillionMicros: n, assumedOutputTokens?: n, byModel?: { model: { inputPerMillionMicros, outputPerMillionMicros } } }
 *   }
 * `pricing` is required when any money limit is set. Tariffs come from the operator here; the provider price lists arrive with.
 */

const FORMAT = 1;
const PERIODS = Object.freeze({ minute: 60, hour: 3600, day: 86400, week: 604800, month: 2592000 });
const ALLOWED = new Set(['budgetFormat', 'scope', 'period', 'models', 'limits', 'perRequest', 'pricing']);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const posInt = (v, max = 1e15) => Number.isSafeInteger(v) && v > 0 && v <= max;

function validate(config) {
  for (const k of Object.keys(config)) if (!ALLOWED.has(k)) throw new Error(`unknown BUDGET config key: ${k}`);
  if (config.budgetFormat !== FORMAT) throw new Error(`config.budgetFormat must be ${FORMAT}`);
  if (config.scope !== 'tenant' && config.scope !== 'caller') throw new Error('config.scope must be tenant or caller');
  if (!Object.prototype.hasOwnProperty.call(PERIODS, config.period)) throw new Error(`config.period must be one of ${Object.keys(PERIODS).join(', ')}`);
  if (config.models !== undefined && !(Array.isArray(config.models) && config.models.length > 0 && config.models.length <= 100 && config.models.every((m) => typeof m === 'string' && m.length > 0 && m.length <= 256))) throw new Error('config.models must be a non-empty array of model names');
  const l = config.limits || {}; const r = config.perRequest || {};
  if (config.limits !== undefined && !isObj(config.limits)) throw new Error('config.limits must be an object');
  if (config.perRequest !== undefined && !isObj(config.perRequest)) throw new Error('config.perRequest must be an object');
  for (const k of Object.keys(l)) if (!['requests', 'tokens', 'costMicros'].includes(k)) throw new Error(`unknown limit: ${k}`);
  for (const k of Object.keys(r)) if (!['maxTokens', 'maxCostMicros', 'maxLatencyMs'].includes(k)) throw new Error(`unknown perRequest limit: ${k}`);
  for (const [k, v] of Object.entries(l)) if (!posInt(v)) throw new Error(`limits.${k} must be a positive integer`);
  for (const [k, v] of Object.entries(r)) if (!posInt(v, k === 'maxLatencyMs' ? 3_600_000 : 1e15)) throw new Error(`perRequest.${k} must be a positive integer`);
  if (Object.keys(l).length === 0 && Object.keys(r).length === 0) throw new Error('a BUDGET rule needs at least one limit');
  const money = l.costMicros !== undefined || r.maxCostMicros !== undefined;
  if (config.pricing !== undefined) {
    const p = config.pricing;
    if (!isObj(p) || Object.keys(p).some((k) => !['currency', 'inputPerMillionMicros', 'outputPerMillionMicros', 'assumedOutputTokens', 'byModel'].includes(k))) throw new Error('config.pricing: { currency, inputPerMillionMicros, outputPerMillionMicros, assumedOutputTokens?, byModel? }');
    if (typeof p.currency !== 'string' || !/^[A-Z]{3}$/.test(p.currency)) throw new Error('pricing.currency is a three-letter code');
    for (const k of ['inputPerMillionMicros', 'outputPerMillionMicros']) if (!(Number.isSafeInteger(p[k]) && p[k] >= 0)) throw new Error(`pricing.${k} must be a non-negative integer`);
    if (p.assumedOutputTokens !== undefined && !posInt(p.assumedOutputTokens, 10_000_000)) throw new Error('pricing.assumedOutputTokens must be a positive integer');
    if (p.byModel !== undefined) {
      if (!isObj(p.byModel) || Object.keys(p.byModel).length > 200) throw new Error('pricing.byModel is an object of at most 200 models');
      for (const [m, v] of Object.entries(p.byModel)) {
        if (isObj(v) && Object.keys(v).some((k) => k !== 'inputPerMillionMicros' && k !== 'outputPerMillionMicros')) throw new Error(`pricing.byModel.${String(m).slice(0, 40)}: only inputPerMillionMicros and outputPerMillionMicros (the currency is the rule's)`);   // F9R-01
        if (['__proto__', 'constructor', 'prototype'].includes(m) || !isObj(v) || !(Number.isSafeInteger(v.inputPerMillionMicros) && v.inputPerMillionMicros >= 0) || !(Number.isSafeInteger(v.outputPerMillionMicros) && v.outputPerMillionMicros >= 0)) throw new Error(`pricing.byModel.${String(m).slice(0, 40)} is invalid`);
      }
    }
  } else if (money) throw new Error('a money limit needs config.pricing');
}

function preprocess(config) { return { ...config, _periodSeconds: PERIODS[config.period] }; }
function evaluate() { return { pass: true }; }

module.exports = { validate, preprocess, evaluate, FORMAT, PERIODS };
