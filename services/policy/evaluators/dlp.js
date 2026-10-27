'use strict';

/**
 * DLP policy rule. Unlike the other rule types it does not decide on the request CONTEXT: it carries the content-protection settings that the DLP stage of
 * the request pipeline (src/core/dlp/dlpService.js) applies to the text of a request and/or response. As an evaluator it therefore always passes; what makes it a policy
 * rule is that it is part of the policy set - validated at load, covered by `policyHash` (so a change of DLP settings changes the hash recorded in the audit chain), managed
 * through the same governance as every other rule.
 *
 * config (format 1):
 *   {
 *     dlpFormat:     1,
 *     direction:     'input' | 'output' | 'both' | 'tool_input' | 'tool_output'   (tool_input: the arguments of a tool call, checked when the call is authorised - DETECT or BLOCK only,
 *                    because the arguments are bound by the action hash and cannot be rewritten; tool_output: what a tool returned, before it is screened and delivered)
 *     action:        'DETECT' | 'REDACT' | 'MASK' | 'BLOCK',
 *     rules:         ['EMAIL', 'FINANCIAL', ...]   detector ids or categories, or ['*']
 * minConfidence: number in [0,1]
 *     onTruncated:   'BLOCK' | 'PASS' (default 'BLOCK': text past the scan cap is not scanned, so REDACT/MASK/BLOCK refuse it)
 *   }
 * A policy file without a DLP rule is unchanged by this feature (no migration); a file WITH one needs the DLP module (enterprise/dlp) installed, else it does not load.
 */

const FORMAT = 1;
const DIRECTIONS = ['input', 'output', 'both', 'tool_input', 'tool_output'];
const ALLOWED = new Set(['dlpFormat', 'direction', 'action', 'rules', 'minConfidence', 'onTruncated', 'classification', 'exfiltration']);
const EXTRA_ACTIONS = ['DETECT', 'BLOCK'];

function validate(config) {
  const dlp = require('../../../src/core/dlp/extensionPoint').get();
  if (!dlp) throw new Error('a DLP policy needs the DLP module (enterprise/dlp), which is not installed');
  for (const k of Object.keys(config)) if (!ALLOWED.has(k)) throw new Error(`unknown DLP config key: ${k}`);
  if (config.dlpFormat !== FORMAT) throw new Error(`config.dlpFormat must be ${FORMAT}`);
  if (!DIRECTIONS.includes(config.direction)) throw new Error(`config.direction must be one of ${DIRECTIONS.join(', ')}`);
  if (!dlp.ACTIONS.includes(config.action)) throw new Error(`config.action must be one of ${dlp.ACTIONS.join(', ')}`);
  if (config.direction === 'tool_input' && !['DETECT', 'BLOCK'].includes(config.action)) throw new Error('a tool_input rule can only DETECT or BLOCK: the arguments are bound by the action hash and cannot be rewritten');
  if (!Array.isArray(config.rules) || config.rules.length === 0 || config.rules.length > 64) throw new Error('config.rules must be a non-empty array (at most 64) of detector ids, categories or "*"');
  const known = new Set([...dlp.RULE_IDS, ...dlp.CATEGORIES, '*']);
  for (const r of config.rules) if (typeof r !== 'string' || !known.has(r)) throw new Error(`unknown DLP rule: ${String(r).slice(0, 40)}`);
  if (config.minConfidence !== undefined && !(typeof config.minConfidence === 'number' && config.minConfidence >= 0 && config.minConfidence <= 1)) throw new Error('config.minConfidence must be a number in [0, 1]');
  if (config.onTruncated !== undefined && config.onTruncated !== 'BLOCK' && config.onTruncated !== 'PASS') throw new Error('config.onTruncated must be BLOCK or PASS');
  const obj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (config.classification !== undefined) {
    const c = config.classification;
    if (!obj(c) || Object.keys(c).some((k) => !['minLevel', 'action', 'markings'].includes(k))) throw new Error('config.classification is { minLevel, action, markings? }');
    if (!dlp.LEVELS.includes(c.minLevel) || c.minLevel === 'PUBLIC') throw new Error('config.classification.minLevel must be INTERNAL, CONFIDENTIAL or RESTRICTED');
    if (!EXTRA_ACTIONS.includes(c.action)) throw new Error('config.classification.action must be DETECT or BLOCK');
    if (c.markings !== undefined && !(obj(c.markings) && Object.entries(c.markings).every(([l, w]) => dlp.LEVELS.includes(l) && Array.isArray(w) && w.length <= 100 && w.every((x) => typeof x === 'string' && x.length >= 3 && x.length <= 80)))) throw new Error('config.classification.markings is { LEVEL: [phrases] }');
  }
  if (config.exfiltration !== undefined) {
    const x = config.exfiltration;
    if (config.direction !== 'output' && config.direction !== 'both') throw new Error('config.exfiltration judges the answer: direction must be output or both');
    if (!obj(x) || Object.keys(x).some((k) => !['action', 'allowHosts', 'bulkThreshold', 'minSeverity'].includes(k))) throw new Error('config.exfiltration is { action, allowHosts?, bulkThreshold?, minSeverity? }');
    if (!EXTRA_ACTIONS.includes(x.action)) throw new Error('config.exfiltration.action must be DETECT or BLOCK');
    if (x.allowHosts !== undefined && !(Array.isArray(x.allowHosts) && x.allowHosts.length <= 100 && x.allowHosts.every((h) => typeof h === 'string' && /^(\*\.)?[a-z0-9.-]{1,253}$/i.test(h)))) throw new Error('config.exfiltration.allowHosts is a list of host names');
    if (x.bulkThreshold !== undefined && !(Number.isInteger(x.bulkThreshold) && x.bulkThreshold >= 2 && x.bulkThreshold <= 10000)) throw new Error('config.exfiltration.bulkThreshold must be an integer in [2, 10000]');
    if (x.minSeverity !== undefined && !['MEDIUM', 'HIGH'].includes(x.minSeverity)) throw new Error('config.exfiltration.minSeverity must be MEDIUM or HIGH');
  }
}

function preprocess(config) {
  // derived defaults live under underscore keys: policyHash ignores those, so the hash of the loaded rule equals the hash of the live rule
  return { ...config, _minConfidence: config.minConfidence ?? 0.6, _onTruncated: config.onTruncated ?? 'BLOCK' };
}

// content enforcement happens in the DLP stage; the context-based engine has nothing to decide here
function evaluate() { return { pass: true }; }

module.exports = { validate, preprocess, evaluate, FORMAT };
