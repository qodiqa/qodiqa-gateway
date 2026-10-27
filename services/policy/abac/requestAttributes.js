'use strict';

/**
 * Builds the SUPPLIED attributes of a /ai/chat (or /verify/v2) request for the ABAC rules. The same function feeds both routes, so a dry run and the real run see the
 * same attributes.
 *
 * Computing the data classification costs a DLP scan, so it is done only when some enabled ABAC rule of the policy set actually mentions a `resource.*` attribute
 * (`policiesNeed`, cached per policy array). Without the DLP module installed the classification attributes are simply absent (a REQUIRE rule on them then refuses: fail closed).
 */

const { CATALOGUE } = require('./attributes');
const PURPOSE_RE = /^[A-Za-z0-9._:/ -]{1,64}$/;

const _needs = new WeakMap();
/** Does any enabled ABAC rule read an attribute in `prefix`? (walks the rule's condition once per policy array) */
function policiesNeed(policies, prefix) {
  if (!Array.isArray(policies)) return false;
  let m = _needs.get(policies); if (!m) { m = new Map(); _needs.set(policies, m); }
  if (m.has(prefix)) return m.get(prefix);
  const mentions = (node) => !!node && (node.all ? node.all.some(mentions) : node.any ? node.any.some(mentions) : node.not ? mentions(node.not) : typeof node.attr === 'string' && node.attr.startsWith(prefix));
  const r = policies.some((p) => p && p.type === 'ABAC' && p.enabled === true && p.config && mentions(p.config.when));
  m.set(prefix, r);
  return r;
}

function textsOf(body) {
  const out = [];
  if (typeof body.prompt === 'string') out.push(body.prompt);
  if (typeof body.system === 'string') out.push(body.system);
  if (Array.isArray(body.messages)) for (const m of body.messages) if (m && typeof m.content === 'string') out.push(m.content);
  return out;
}

/** The model a request will be served with: the caller's, else the provider's configured default (the same resolution the route uses), else undefined. */
function effectiveModel(body, provider) {
  if (body && typeof body.model === 'string' && body.model) return body.model;
  try { const m = provider ? require('../../providers/config').resolveDefaultModel(provider) : null; return typeof m === 'string' && m ? m : undefined; } catch { return undefined; }
}

/** An UPPER estimate of the tokens in the texts: 1/3 per character, and 2 per character beyond U+02FF (CJK, emoji and other scripts that tokenise per character or worse). */
function estimateTokens(texts) {
  let n = 0;
  for (const t of texts) for (const ch of t) n += ch.codePointAt(0) > 0x2ff ? 2 : 1 / 3;
  return Math.ceil(n);
}

/** @returns {object} attributes valid for services/policy/abac/attributes.js#sanitizeSupplied */
function buildRequestAttributes(body, policies, provider = null) {
  const out = {};
  if (!body || typeof body !== 'object') return out;
  const model = effectiveModel(body, provider);                       // F8V-01: the model the provider will actually be called with, also when the caller omitted it
  if (typeof model === 'string' && model.length <= 256) out['request.model'] = model;
  if (typeof body.purpose === 'string' && PURPOSE_RE.test(body.purpose)) out['request.purpose'] = body.purpose;
  if (typeof body.dataRegion === 'string' && PURPOSE_RE.test(body.dataRegion)) out['request.dataRegion'] = body.dataRegion;
  out['request.stream'] = body.stream === true;
  const texts = textsOf(body);
  const chars = texts.reduce((n, t) => n + t.length, 0);
  out['request.promptChars'] = chars;
  out['request.messages'] = Array.isArray(body.messages) ? body.messages.length : 1;
  out['cost.estimatedTokens'] = estimateTokens(texts);                       // an UPPER estimate (see estimateTokens)
  if (policiesNeed(policies, 'resource.')) {
    try {
      const dlp = require('../../../src/core/dlp/extensionPoint').get();
      if (dlp) {
        const cats = new Set(); let level = 'PUBLIC';
        for (const t of texts) {
          const s = dlp.scan(t, { rules: ['*'], minConfidence: 0.6 });
          s.findings.forEach((f) => cats.add(f.rule));
          const c = dlp.classify(t, s.findings);
          if (dlp.rank(c.level) > dlp.rank(level)) level = c.level;
        }
        out['resource.classification'] = level;
        out['resource.categories'] = [...cats].sort().slice(0, 32);
      }
    } catch { /* attributes stay absent: a REQUIRE rule on them refuses */ }
  }
  return out;
}

/** As buildRequestAttributes, taking the policy GETTER: if the getter throws, the attributes are simply absent and checkPolicy reaches its own fail-closed branch for the same failure. */
function buildFor(body, getPolicies, provider = null) {
  let policies;
  try { policies = typeof getPolicies === 'function' ? getPolicies() : null; } catch { return null; }
  return buildRequestAttributes(body, policies, provider);
}

module.exports = { effectiveModel, estimateTokens, buildFor, buildRequestAttributes, policiesNeed, PURPOSE_RE, CATALOGUE };
