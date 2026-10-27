'use strict';

/**
 * ABAC policy rule: an attribute-based rule in the declarative condition language of services/policy/abac/condition.js.
 *
 *   {
 *     abacFormat: 1,
 *     effect:     'DENY' | 'REQUIRE',        DENY: refuse the request when the condition is TRUE. REQUIRE: refuse unless the condition is TRUE (a missing attribute refuses)
 *     when:       <condition>,
 *     reason:     'LABEL',                   [A-Z0-9_]{1,32}; the refusal reason is ABAC_<LABEL>
 * appliesTo: 'request' | 'tool' default 'request'. 'tool' rules are evaluated when a tool call is AUTHORISED, not on /ai/chat
 *   }
 *
 * Several rules are evaluated in priority order like every other rule; the first refusal decides. The rule is hashed with the policy set (policyHash), validated when loaded,
 * and its condition is bounded (depth, nodes, values), so evaluation is always cheap and always terminates.
 */

const condition = require('../abac/condition');

const FORMAT = condition.FORMAT;
const ALLOWED = new Set(['abacFormat', 'effect', 'when', 'reason', 'appliesTo']);
const LABEL_RE = /^[A-Z0-9_]{1,32}$/;

function validate(config) {
  for (const k of Object.keys(config)) if (!ALLOWED.has(k)) throw new Error(`unknown ABAC config key: ${k}`);
  if (config.abacFormat !== FORMAT) throw new Error(`config.abacFormat must be ${FORMAT}`);
  if (config.effect !== 'DENY' && config.effect !== 'REQUIRE') throw new Error('config.effect must be DENY or REQUIRE');
  if (typeof config.reason !== 'string' || !LABEL_RE.test(config.reason)) throw new Error('config.reason must be a label of 1-32 characters [A-Z0-9_]');
  if (config.appliesTo !== undefined && config.appliesTo !== 'request' && config.appliesTo !== 'tool') throw new Error('config.appliesTo must be request or tool');
  condition.validate(config.when);
}

function preprocess(config) { return { ...config, _when: condition.prepare(config.when), _appliesTo: config.appliesTo || 'request' }; }

function decide(config, context) {
  const hit = condition.evaluate(config._when, context);
  if (config.effect === 'DENY' && hit) return { pass: false, reason: `ABAC_${config.reason}` };
  if (config.effect === 'REQUIRE' && !hit) return { pass: false, reason: `ABAC_${config.reason}` };
  return { pass: true };
}

function evaluate(context, config) {
  if (config._appliesTo === 'tool') return { pass: true };             // tool rules are evaluated by evaluateTool when a call is authorised
  if (config._appliesTo !== 'request' || !config._when) throw new Error('ABAC rule was not preprocessed');   // F8V-02: never a silent PASS (the engine turns this into EVALUATOR_ERROR)
  return decide(config, context);
}

/** Tool scope: `attributes` as supplied by the authorise route (tool.*, agent.id) on top of the same built-ins; first refusal wins. */
function evaluateTool(policies, context) {
  for (const p of policies || []) {
    if (!p || p.type !== 'ABAC' || p.enabled !== true || !p.config) continue;
    if (p.config._appliesTo === 'request') continue;
    // gate G-02: a rule that was never preprocessed (no derived fields) is not skipped as "not a tool rule" - it refuses, like the engine's EVALUATOR_ERROR for request rules
    if (p.config._appliesTo !== 'tool' || !p.config._when) return { pass: false, reason: 'EVALUATOR_ERROR', policyId: p.id };
    const r = decide(p.config, context);
    if (!r.pass) return { pass: false, reason: r.reason, policyId: p.id };
  }
  return { pass: true };
}

module.exports = { validate, preprocess, evaluate, evaluateTool, FORMAT };
