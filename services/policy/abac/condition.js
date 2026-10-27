'use strict';

/**
 * The condition language of ABAC rules: a small, declarative, VERSIONED JSON tree - no code, no regular expressions, no loops - so a rule can always be read, hashed,
 * simulated and evaluated in bounded time.
 *
 *   node := { all: [node, ...] } | { any: [node, ...] } | { not: node } | { attr: <name>, op: <op>, value?: <scalar | array> }
 *
 *   ops   eq ne | in notIn (value: array) | lt lte gt gte (numbers) | between (value: [lo, hi]) | exists notExists | startsWith endsWith (strings) | contains (string in string, or
 *         element in string[]) | cidr (value: array of CIDRs; the attribute is an IP) | hasAny hasAll (string[] attribute against an array)
 *
 * Bounds: depth <= 6, <= 100 nodes, arrays <= 200 values, strings <= 256 characters. `attr` must be in the catalogue (attributes.js) and the operator and value must fit the
 * attribute's type - all checked when the policy is LOADED.
 *
 * Missing attributes: a comparison on an attribute that is not available is FALSE (ne, notIn and notExists are true only when the attribute is absent or different, by their plain
 * meaning). Rule effects (abac.js) decide what that means: a DENY rule fires when its condition is true, so a missing attribute does not deny; a REQUIRE rule denies unless its
 * condition is true, so a missing attribute denies. Write allow-lists as REQUIRE.
 */

const net = require('net');
const { CATALOGUE, resolve } = require('./attributes');
const inCatalogue = (name) => Object.prototype.hasOwnProperty.call(CATALOGUE, name);

const FORMAT = 1;
const MAX_DEPTH = 6; const MAX_NODES = 100; const MAX_VALUES = 200; const MAX_STRING = 256;
const OPS = Object.freeze(['eq', 'ne', 'in', 'notIn', 'lt', 'lte', 'gt', 'gte', 'between', 'exists', 'notExists', 'startsWith', 'endsWith', 'contains', 'cidr', 'hasAny', 'hasAll']);
const NUMERIC_OPS = new Set(['lt', 'lte', 'gt', 'gte', 'between']);
const STRING_OPS = new Set(['startsWith', 'endsWith']);
const ARRAY_VALUE_OPS = new Set(['in', 'notIn', 'cidr', 'hasAny', 'hasAll']);
const NO_VALUE_OPS = new Set(['exists', 'notExists']);
const isScalar = (v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function validateCidr(c) {
  if (typeof c !== 'string') return false;
  const slash = c.lastIndexOf('/'); if (slash < 1) return false;
  const base = c.slice(0, slash); const prefix = Number(c.slice(slash + 1));
  const fam = net.isIPv4(base) ? 4 : net.isIPv6(base) ? 6 : 0;
  return fam !== 0 && Number.isInteger(prefix) && prefix >= 0 && prefix <= (fam === 4 ? 32 : 128);
}

/** Throws Error(message) naming the problem; returns the number of nodes. */
function validate(node, path = 'when', depth = 1, counter = { n: 0 }) {
  if (++counter.n > MAX_NODES) throw new Error(`${path}: more than ${MAX_NODES} nodes`);
  if (depth > MAX_DEPTH) throw new Error(`${path}: deeper than ${MAX_DEPTH} levels`);
  if (!isObj(node)) throw new Error(`${path}: a condition is an object`);
  const keys = Object.keys(node);
  if (keys.includes('all') || keys.includes('any')) {
    const k = keys.includes('all') ? 'all' : 'any';
    if (keys.length !== 1) throw new Error(`${path}: ${k} stands alone`);
    if (!Array.isArray(node[k]) || node[k].length === 0 || node[k].length > MAX_NODES) throw new Error(`${path}.${k}: a non-empty array of conditions`);
    node[k].forEach((c, i) => validate(c, `${path}.${k}[${i}]`, depth + 1, counter));
    return counter.n;
  }
  if (keys.includes('not')) {
    if (keys.length !== 1) throw new Error(`${path}: not stands alone`);
    validate(node.not, `${path}.not`, depth + 1, counter);
    return counter.n;
  }
  for (const k of keys) if (!['attr', 'op', 'value'].includes(k)) throw new Error(`${path}: unknown key ${k}`);
  const def = inCatalogue(node.attr) ? CATALOGUE[node.attr] : undefined;     // own entries only: no prototype-chain names (constructor, toString, ...)
  if (!def) throw new Error(`${path}: unknown attribute ${String(node.attr).slice(0, 60)}`);
  if (!OPS.includes(node.op)) throw new Error(`${path}: unknown operator ${String(node.op).slice(0, 30)}`);
  const op = node.op; const t = def.type; const v = node.value;
  if (NO_VALUE_OPS.has(op)) { if (v !== undefined) throw new Error(`${path}: ${op} takes no value`); return counter.n; }
  if (v === undefined) throw new Error(`${path}: ${op} needs a value`);
  const checkStr = (s) => typeof s === 'string' && s.length <= MAX_STRING;
  if (ARRAY_VALUE_OPS.has(op)) {
    if (!Array.isArray(v) || v.length === 0 || v.length > MAX_VALUES) throw new Error(`${path}: ${op} needs a non-empty array of at most ${MAX_VALUES} values`);
    if (op === 'cidr') { if (node.attr !== 'env.ip' || !v.every(validateCidr)) throw new Error(`${path}: cidr compares a string attribute with CIDRs`); }
    else if (op === 'hasAny' || op === 'hasAll') { if (t !== 'string[]' || !v.every(checkStr)) throw new Error(`${path}: ${op} compares a string[] attribute with strings`); }
    else if (!v.every((x) => isScalar(x) && (typeof x !== 'string' || checkStr(x)))) throw new Error(`${path}: ${op} values are scalars`);
    if ((op === 'in' || op === 'notIn') && t === 'string[]') throw new Error(`${path}: use hasAny / hasAll for a string[] attribute`);
    if ((op === 'in' || op === 'notIn') && !v.every((x) => typeof x === t)) throw new Error(`${path}: values must be ${t}`);
    return counter.n;
  }
  if (NUMERIC_OPS.has(op)) {
    if (t !== 'number') throw new Error(`${path}: ${op} needs a number attribute`);
    if (op === 'between') { if (!(Array.isArray(v) && v.length === 2 && v.every((x) => typeof x === 'number' && Number.isFinite(x)) && v[0] <= v[1])) throw new Error(`${path}: between needs [low, high]`); }
    else if (!(typeof v === 'number' && Number.isFinite(v))) throw new Error(`${path}: ${op} needs a number`);
    return counter.n;
  }
  if (STRING_OPS.has(op)) { if (t !== 'string' || !checkStr(v) || v.length === 0) throw new Error(`${path}: ${op} needs a string attribute and a non-empty string`); return counter.n; }
  if (op === 'contains') { if (!(t === 'string' || t === 'string[]') || !checkStr(v) || v.length === 0) throw new Error(`${path}: contains needs a string or string[] attribute and a string`); return counter.n; }
  // eq / ne
  if (t === 'string[]') throw new Error(`${path}: use contains / hasAny / hasAll for a string[] attribute`);
  if (typeof v !== t || (t === 'string' && !checkStr(v))) throw new Error(`${path}: value must be ${t}`);
  return counter.n;
}

/** Compile the CIDR lists once (kept under an underscore key so that policyHash ignores them). */
function prepare(node) {
  if (node.all) return { ...node, all: node.all.map(prepare) };
  if (node.any) return { ...node, any: node.any.map(prepare) };
  if (node.not) return { ...node, not: prepare(node.not) };
  if (node.op === 'cidr') {
    const bl = new net.BlockList();
    for (const c of node.value) { const i = c.lastIndexOf('/'); const base = c.slice(0, i); bl.addSubnet(base, Number(c.slice(i + 1)), net.isIPv4(base) ? 'ipv4' : 'ipv6'); }
    return { ...node, _blockList: bl };
  }
  return node;
}

function leaf(node, context) {
  const val = resolve(context, node.attr);
  const v = node.value;
  switch (node.op) {
    case 'exists': return val !== undefined;
    case 'notExists': return val === undefined;
    case 'eq': return val !== undefined && val === v;
    case 'ne': return val === undefined || val !== v;
    case 'in': return val !== undefined && v.includes(val);
    case 'notIn': return val === undefined || !v.includes(val);
    case 'lt': return typeof val === 'number' && val < v;
    case 'lte': return typeof val === 'number' && val <= v;
    case 'gt': return typeof val === 'number' && val > v;
    case 'gte': return typeof val === 'number' && val >= v;
    case 'between': return typeof val === 'number' && val >= v[0] && val <= v[1];
    case 'startsWith': return typeof val === 'string' && val.startsWith(v);
    case 'endsWith': return typeof val === 'string' && val.endsWith(v);
    case 'contains': return typeof val === 'string' ? val.includes(v) : Array.isArray(val) && val.includes(v);
    case 'hasAny': return Array.isArray(val) && val.some((x) => v.includes(x));
    case 'hasAll': return Array.isArray(val) && v.every((x) => val.includes(x));
    case 'cidr': {
      if (typeof val !== 'string') return false;
      const fam = net.isIPv4(val) ? 'ipv4' : net.isIPv6(val) ? 'ipv6' : null;
      return fam !== null && node._blockList.check(val, fam);
    }
    default: return false;
  }
}

function evaluate(node, context) {
  if (node.all) return node.all.every((c) => evaluate(c, context));
  if (node.any) return node.any.some((c) => evaluate(c, context));
  if (node.not) return !evaluate(node.not, context);
  return leaf(node, context);
}

module.exports = { FORMAT, OPS, validate, prepare, evaluate, MAX_DEPTH, MAX_NODES };
