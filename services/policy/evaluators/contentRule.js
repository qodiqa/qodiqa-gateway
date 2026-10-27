'use strict';

/**
 * CONTENT_RULE policy rule: custom content-blocking rules of the tenant - word lists, phrase lists and regular expressions - with a score threshold that can differ per model
 * and per declared purpose ("domain"). Like DLP and BUDGET it does not decide on the request context: it is the governed, hashed statement of the rule, applied to the text of the
 * request and/or answer by src/core/content/contentStage.js. As an evaluator it always passes.
 *
 *   {
 *     contentFormat: 1,
 *     direction: 'input' | 'output' | 'both',
 *     action:    'BLOCK' | 'DETECT',
 *     items: [ { id: 'competitor-x', kind: 'word' | 'phrase' | 'regex', value: '...', caseInsensitive?: true (default), weight?: 1 }, ... ],      at most 200
 *     threshold: 1,                                                    the rule fires when the weights of the DISTINCT items that matched add up to at least this
 *     thresholds: [ { models?: [...], purposes?: [...], threshold: n } ],   per model and/or purpose: the first entry whose scope matches replaces `threshold`
 *     scope:     { models?: [...], purposes?: [...] }                  optional: the rule applies only to these models / declared purposes (an unknown model or a missing
 *                                                                      declaration counts as in scope: the stricter reading)
 *   }
 * Regular expressions run on the linear-time engine (services/policy/content/safeRegex.js): a pattern cannot cause catastrophic backtracking and is bounded at load. The matched text is
 * never logged or returned: only the item ids.
 */

const safe = require('../content/safeRegex');

const FORMAT = 1;
const ALLOWED = new Set(['contentFormat', 'direction', 'action', 'items', 'threshold', 'thresholds', 'scope']);
const ID_RE = /^[A-Za-z0-9._-]{1,48}$/;
const MAX_ITEMS = 200; const MAX_VALUE = 512;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const strList = (v) => Array.isArray(v) && v.length > 0 && v.length <= 100 && v.every((x) => typeof x === 'string' && x.length > 0 && x.length <= 256);

function validate(config) {
  for (const k of Object.keys(config)) if (!ALLOWED.has(k)) throw new Error(`unknown CONTENT_RULE config key: ${k}`);
  if (config.contentFormat !== FORMAT) throw new Error(`config.contentFormat must be ${FORMAT}`);
  if (!['input', 'output', 'both'].includes(config.direction)) throw new Error('config.direction must be input, output or both');
  if (config.action !== 'BLOCK' && config.action !== 'DETECT') throw new Error('config.action must be BLOCK or DETECT');
  if (!Array.isArray(config.items) || config.items.length === 0 || config.items.length > MAX_ITEMS) throw new Error(`config.items must be an array of 1..${MAX_ITEMS} items`);
  const ids = new Set();
  for (const it of config.items) {
    if (!isObj(it) || Object.keys(it).some((k) => !['id', 'kind', 'value', 'caseInsensitive', 'weight'].includes(k))) throw new Error('an item is { id, kind, value, caseInsensitive?, weight? }');
    if (typeof it.id !== 'string' || !ID_RE.test(it.id) || ids.has(it.id)) throw new Error(`item ids are unique labels of 1-48 characters [A-Za-z0-9._-]: ${String(it.id).slice(0, 30)}`);
    ids.add(it.id);
    if (!['word', 'phrase', 'regex'].includes(it.kind)) throw new Error(`item ${it.id}: kind is word, phrase or regex`);
    if (typeof it.value !== 'string' || it.value.length === 0 || it.value.length > MAX_VALUE) throw new Error(`item ${it.id}: value is a string of 1..${MAX_VALUE} characters`);
    if (it.kind === 'word' && /\s/.test(it.value.trim())) throw new Error(`item ${it.id}: a word has no spaces (use a phrase)`);
    if (it.caseInsensitive !== undefined && typeof it.caseInsensitive !== 'boolean') throw new Error(`item ${it.id}: caseInsensitive is a boolean`);
    if (it.weight !== undefined && !(Number.isInteger(it.weight) && it.weight >= 1 && it.weight <= 1000)) throw new Error(`item ${it.id}: weight is an integer 1..1000`);
    if (it.kind === 'regex') { try { safe.compile(it.value); } catch (e) { throw new Error(`item ${it.id}: ${e.message}`); } }
  }
  const total = config.items.reduce((n, it) => n + (it.weight || 1), 0);
  if (config.threshold !== undefined && !(Number.isInteger(config.threshold) && config.threshold >= 1 && config.threshold <= 1_000_000)) throw new Error('config.threshold is a positive integer');
  if ((config.threshold || 1) > total) throw new Error('config.threshold is higher than the weights of all items together: the rule could never fire');
  if (config.thresholds !== undefined) {
    if (!Array.isArray(config.thresholds) || config.thresholds.length > 50) throw new Error('config.thresholds is an array of at most 50 entries');
    for (const t of config.thresholds) {
      if (!isObj(t) || Object.keys(t).some((k) => !['models', 'purposes', 'threshold'].includes(k)) || !Number.isInteger(t.threshold) || t.threshold < 1) throw new Error('a thresholds entry is { models?, purposes?, threshold }');
      if (t.models !== undefined && !strList(t.models)) throw new Error('thresholds.models is a list of model names');
      if (t.purposes !== undefined && !strList(t.purposes)) throw new Error('thresholds.purposes is a list of purposes');
      if (t.models === undefined && t.purposes === undefined) throw new Error('a thresholds entry names models and/or purposes');
    }
  }
  if (config.scope !== undefined) {
    if (!isObj(config.scope) || Object.keys(config.scope).some((k) => !['models', 'purposes'].includes(k))) throw new Error('config.scope is { models?, purposes? }');
    if (config.scope.models !== undefined && !strList(config.scope.models)) throw new Error('scope.models is a list of model names');
    if (config.scope.purposes !== undefined && !strList(config.scope.purposes)) throw new Error('scope.purposes is a list of purposes');
  }
}

function preprocess(config) {
  const compiled = config.items.map((it) => (it.kind === 'regex' ? safe.compile(it.value, { caseInsensitive: it.caseInsensitive !== false }) : null));
  return { ...config, _compiled: compiled, _threshold: config.threshold || 1 };
}

function evaluate() { return { pass: true }; }

module.exports = { validate, preprocess, evaluate, FORMAT };
