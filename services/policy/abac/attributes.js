'use strict';

/**
 * The attribute catalogue of the ABAC rule language. A rule may only name an attribute listed here, so a typo fails when the policy is loaded instead of silently never
 * matching. Attributes come from three places:
 *   built-in    derived from the evaluation context the engine already validates (user, caller, tenant, provider, time, IP);
 *   supplied    set by the request pipeline (`context.attributes`): what the request declares or what the gateway computed about it (model, declared purpose, classification, ...);
 *   operational read from the process at evaluation time (`ops.mode`).
 *
 * Types: 'string' | 'number' | 'boolean' | 'string[]'. A value that is not available is `undefined`: comparisons on a missing attribute are false (see condition.js for what that means
 * for DENY and REQUIRE rules - REQUIRE fails closed).
 */

const CATALOGUE = Object.freeze({
  // who
  'subject.userId':            { type: 'string',   source: 'built-in',    doc: 'the verified signing key (key attribution)' },
  'subject.callerId':          { type: 'string',   source: 'built-in',    doc: 'the authenticated caller identity bound into the artifact' },
  'tenant.id':                 { type: 'string',   source: 'built-in',    doc: 'the tenant' },
  // what is asked
  'request.provider':          { type: 'string',   source: 'built-in',    doc: 'the provider named by the artifact' },
  'request.model':             { type: 'string',   source: 'supplied',    doc: 'the model named in the request body' },
  'request.purpose':           { type: 'string',   source: 'supplied',    doc: 'the purpose the caller DECLARES (a claim, not a proof)' },
  'request.dataRegion':        { type: 'string',   source: 'supplied',    doc: 'the region the caller DECLARES the data comes from (a claim)' },
  'request.stream':            { type: 'boolean',  source: 'supplied',    doc: 'whether the response is streamed' },
  'request.promptChars':       { type: 'number',   source: 'supplied',    doc: 'characters in the prompt or conversation' },
  'request.messages':          { type: 'number',   source: 'supplied',    doc: 'messages in the conversation (1 for a single prompt)' },
  // what the data is
  'resource.classification':   { type: 'string',   source: 'supplied',    doc: 'PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED, computed by the DLP classifier when it is installed' },
  'resource.categories':       { type: 'string[]', source: 'supplied',    doc: 'DLP rule ids found in the request (EMAIL, CARD, ...)' },
  // when / where / how the platform is doing
  'env.hour':                  { type: 'number',   source: 'built-in',    doc: 'hour of the day, UTC, 0-23' },
  'env.dow':                   { type: 'number',   source: 'built-in',    doc: 'day of the week, UTC, 0 = Sunday' },
  'env.ip':                    { type: 'string',   source: 'built-in',    doc: 'the client IP' },
  'ops.mode':                  { type: 'string',   source: 'operational', doc: 'normal | degraded | maintenance | incident (QODIQA_OPS_MODE)' },
  // tool calls
  'tool.server':               { type: 'string',   source: 'supplied',    doc: 'the MCP server of a tool call' },
  'tool.name':                 { type: 'string',   source: 'supplied',    doc: 'the tool' },
  'tool.class':                { type: 'string',   source: 'supplied',    doc: 'the action class of the tool' },
  'tool.reversible':           { type: 'boolean',  source: 'supplied',    doc: 'whether the tool is reversible' },
  'agent.id':                  { type: 'string',   source: 'supplied',    doc: 'the agent making a tool call' },
  // cost
  'cost.estimatedTokens':      { type: 'number',   source: 'supplied',    doc: 'an upper estimate of the tokens this request will use' },
});

const OPS_MODES = Object.freeze(['normal', 'degraded', 'maintenance', 'incident']);
const SUPPLIED = Object.freeze(Object.keys(CATALOGUE).filter((k) => CATALOGUE[k].source === 'supplied'));
const MAX_STRING = 256; const MAX_ARRAY = 32;

/** Validates the attributes a pipeline supplies (types as catalogued; unknown names refused). Returns a frozen copy. */
function sanitizeSupplied(attrs) {
  const out = {};
  if (attrs === undefined || attrs === null) return Object.freeze(out);
  if (typeof attrs !== 'object' || Array.isArray(attrs)) throw new TypeError('attributes must be a plain object');
  for (const [k, v] of Object.entries(attrs)) {
    const def = CATALOGUE[k];
    if (!def || def.source !== 'supplied') throw new TypeError(`unknown or non-suppliable attribute: ${String(k).slice(0, 60)}`);
    if (v === undefined || v === null) continue;
    if (def.type === 'string' && !(typeof v === 'string' && v.length <= MAX_STRING)) throw new TypeError(`attribute ${k} must be a string of at most ${MAX_STRING}`);
    if (def.type === 'number' && !(typeof v === 'number' && Number.isFinite(v))) throw new TypeError(`attribute ${k} must be a finite number`);
    if (def.type === 'boolean' && typeof v !== 'boolean') throw new TypeError(`attribute ${k} must be a boolean`);
    if (def.type === 'string[]' && !(Array.isArray(v) && v.length <= MAX_ARRAY && v.every((x) => typeof x === 'string' && x.length <= 64))) throw new TypeError(`attribute ${k} must be an array of at most ${MAX_ARRAY} short strings`);
    out[k] = def.type === 'string[]' ? Object.freeze([...v]) : v;
  }
  return Object.freeze(out);
}

function opsMode(env = process.env) {
  const m = env.QODIQA_OPS_MODE;
  return OPS_MODES.includes(m) ? m : 'normal';
}

/** The value of one attribute for an evaluation context (see services/policy/context.js), or undefined. */
function resolve(context, name) {
  switch (name) {
    case 'subject.userId': return context.userId ?? undefined;
    case 'subject.callerId': return context.callerId ?? undefined;
    case 'tenant.id': return context.tenantId ?? undefined;
    case 'request.provider': return context.action ?? undefined;
    case 'env.ip': return context.ip ?? undefined;
    case 'env.hour': return typeof context.timestamp === 'number' ? new Date(context.timestamp * 1000).getUTCHours() : undefined;
    case 'env.dow': return typeof context.timestamp === 'number' ? new Date(context.timestamp * 1000).getUTCDay() : undefined;
    case 'ops.mode': return opsMode();
    default: return context.attributes ? context.attributes[name] : undefined;
  }
}

module.exports = { CATALOGUE, SUPPLIED, OPS_MODES, sanitizeSupplied, resolve, opsMode };
