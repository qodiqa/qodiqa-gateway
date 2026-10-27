'use strict';

/**
 * The DLP stage of the request pipeline. Applies the DLP policy rules of the tenant's effective policy set to the text of a request body (direction 'input') or of
 * the model's answer (direction 'output'), and reports what happened as audit events that carry BOTH hashes - the text as received and the text as forwarded - so the
 * log of a transformed request can never be mistaken for the request that arrived.
 *
 *   dlpPolicies(policies, direction)                         the enabled DLP rules for a direction, in priority order
 *   applyToBody(body, policies, ctx)  -> { blocked, reason?, body, events }       input: `prompt`, or `system` + `messages[].content`
 *   applyToText(text, policies, ctx)  -> { blocked, reason?, text, events }       output
 *   recordEvents(events, ctx)                                writes DLP_TRANSFORM chain entries under audit schema v8, else a structured event (never the values)
 *
 * Fail closed: a configured DLP rule that cannot run (module missing, REDACT without a token key) blocks the request (DLP_UNAVAILABLE); it is never skipped.
 * The token key (QODIQA_DLP_TOKEN_KEY, at least 32 characters) is a per-deployment secret: stable tokens are HMACs under it, so they cannot be reversed or tabled.
 */

const crypto = require('crypto');
const { emit } = require('../../../services/logger');
const ext = require('./extensionPoint');

const sha256Hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function tokenKey(env = process.env) {
  const k = env.QODIQA_DLP_TOKEN_KEY;
  return typeof k === 'string' && k.length >= 32 ? Buffer.from(k, 'utf8') : null;
}

function dlpPolicies(policies, direction) {
  const chat = direction === 'input' || direction === 'output';                       // 'both' means the two chat directions, not the tool ones
  return (policies || []).filter((p) => p && p.type === 'DLP' && p.enabled !== false && p.config && (p.config.direction === direction || (chat && p.config.direction === 'both')))
    .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0) || String(a.id).localeCompare(String(b.id)));
}

const unavailable = (why) => ({ blocked: true, reason: 'DLP_UNAVAILABLE', detail: why, events: [] });

function _run(dlp, texts, policy, key) {
  const c = policy.config;
  const joined = texts;                                 // an array of strings; each is scanned on its own
  const out = []; const all = []; let blocked = false;
  const before = sha256Hex(JSON.stringify(joined));
  for (const t of joined) {
    const r = dlp.transform(t, { action: c.action, rules: c.rules, minConfidence: c._minConfidence ?? c.minConfidence ?? 0.6, tokenKey: key, onTruncated: c._onTruncated ?? c.onTruncated ?? 'BLOCK' });
    all.push(r); out.push(r.blocked ? t : r.text); if (r.blocked) blocked = true;
  }
  const rules = [...new Set(all.flatMap((r) => r.rules))].sort();
  const findings = all.reduce((n, r) => n + r.findings.length, 0);
  const after = sha256Hex(JSON.stringify(out));
  return { texts: out, blocked, event: { policyId: policy.id, action: c.action, rules, findings, truncated: all.some((r) => r.truncated), inputHashBefore: before, inputHashAfter: blocked ? before : after } };
}

function _needsKey(ps) { return ps.some((p) => p.config.action === 'REDACT'); }

const SEVERITY_RANK = { MEDIUM: 1, HIGH: 2 };
const noText = (policy, action, rules, blocked, hashOf, extra = {}) => ({ policyId: policy.id, action, rules, findings: rules.length, truncated: false, inputHashBefore: hashOf, inputHashAfter: hashOf, blocked, ...extra });

/** classification of the text and, for an answer, exfiltration signals. Evaluated on the text AS RECEIVED by this stage (before this rule's own transformation). */
function _extras(dlp, texts, policy, direction, ctx) {
  const c = policy.config; const events = []; let blocked = false;
  const hash = sha256Hex(JSON.stringify(texts));
  const minConf = c._minConfidence ?? c.minConfidence ?? 0.6;
  const scans = texts.map((t) => dlp.scan(t, { rules: ['*'], minConfidence: minConf }));
  if (c.classification) {
    let top = null;
    texts.forEach((t, i) => { const r = dlp.classify(t, scans[i].findings, { markings: c.classification.markings }); if (!top || dlp.rank(r.level) > dlp.rank(top.level)) top = r; });
    if (top && dlp.rank(top.level) >= dlp.rank(c.classification.minLevel)) {
      const stop = c.classification.action === 'BLOCK';
      events.push(noText(policy, c.classification.action, [`CLASS:${top.level}`], stop, hash, { direction, classification: { level: top.level, confidence: top.confidence } }));
      if (stop) blocked = true;
    }
  }
  if (c.exfiltration && direction === 'output') {
    const input = (ctx && ctx.inputTexts) || []; const inputValues = input.flatMap((t) => dlp.scan(t, { rules: ['*'], minConfidence: minConf }).findings.map((f) => f.value));
    const min = SEVERITY_RANK[c.exfiltration.minSeverity || 'MEDIUM'];
    const sigs = texts.flatMap((t, i) => dlp.exfiltration(t, scans[i].findings, { inputFindingValues: inputValues, inputText: input.join(String.fromCharCode(10)), allowHosts: c.exfiltration.allowHosts || [], bulkThreshold: c.exfiltration.bulkThreshold || 10 }).signals)
      .filter((s) => SEVERITY_RANK[s.severity] >= min);
    if (sigs.length > 0) {
      const stop = c.exfiltration.action === 'BLOCK';
      events.push(noText(policy, c.exfiltration.action, [...new Set(sigs.map((s) => `EXFIL:${s.signal}`))].sort(), stop, hash, { direction, exfiltration: sigs.map((s) => ({ signal: s.signal, severity: s.severity, confidence: s.confidence })) }));
      if (stop) blocked = true;
    }
  }
  return { events, blocked };
}

function _apply(texts, policies, direction, ctx) {
  const ps = dlpPolicies(policies, direction);
  if (ps.length === 0) return { blocked: false, texts, events: [] };
  const dlp = ext.get();
  if (!dlp) return unavailable('the DLP module is not installed');
  const key = tokenKey();
  if (_needsKey(ps) && !key) return unavailable('REDACT needs QODIQA_DLP_TOKEN_KEY (at least 32 characters)');
  let cur = texts; const events = [];
  for (const p of ps) {
    let r;
    try { r = _run(dlp, p.config.action === 'BLOCK' ? texts : cur, p, key); } catch (e) { return unavailable(`policy ${p.id}: ${String(e && e.message).slice(0, 120)}`); }
    // classification and exfiltration judge the text as it arrived at this rule
    let x;
    try { x = (p.config.classification || p.config.exfiltration) ? _extras(dlp, texts, p, direction, ctx) : { events: [], blocked: false }; } catch (e) { return unavailable(`policy ${p.id}: ${String(e && e.message).slice(0, 120)}`); }
    events.push(...x.events);
    // a rule that found nothing leaves no trace except in DETECT-and-above runs with findings: record only transformations / detections / blocks
    if (r.event.findings > 0 || r.blocked) events.push({ ...r.event, direction, blocked: r.blocked });
    if (x.blocked || r.blocked) return { blocked: true, reason: 'DLP_BLOCKED', texts, events };
    if (p.config.action !== 'BLOCK') cur = r.texts;
  }
  return { blocked: false, texts: cur, events };
}

/** Input: returns a COPY of the body with the transformed texts. */
function applyToBody(body, policies, ctx) {
  const refs = [];                                                     // [{ get, set }]
  const copy = JSON.parse(JSON.stringify(body));
  if (typeof copy.prompt === 'string') refs.push(['prompt']);
  if (typeof copy.system === 'string') refs.push(['system']);
  if (Array.isArray(copy.messages)) copy.messages.forEach((m, i) => { if (m && typeof m.content === 'string') refs.push(['messages', i, 'content']); });
  const texts = refs.map((p) => p.reduce((o, k) => o[k], copy));
  const r = _apply(texts, policies, 'input', ctx);
  if (r.blocked) return { blocked: true, reason: r.reason, detail: r.detail, body, events: r.events };
  refs.forEach((p, i) => { const last = p[p.length - 1]; const parent = p.slice(0, -1).reduce((o, k) => o[k], copy); parent[last] = r.texts[i]; });
  return { blocked: false, body: copy, events: r.events, changed: r.events.some((e) => e.inputHashBefore !== e.inputHashAfter) };
}

/** The texts of a request body, as the input stage sees them (used to tell what the user supplied from what the answer added). */
function textsOf(body) {
  const out = [];
  if (body && typeof body.prompt === 'string') out.push(body.prompt);
  if (body && typeof body.system === 'string') out.push(body.system);
  if (body && Array.isArray(body.messages)) for (const m of body.messages) if (m && typeof m.content === 'string') out.push(m.content);
  return out;
}

function applyToText(text, policies, ctx) {
  const r = _apply([text], policies, 'output', ctx);
  if (r.blocked) return { blocked: true, reason: r.reason, detail: r.detail, text, events: r.events };
  return { blocked: false, text: r.texts[0], events: r.events, changed: r.events.some((e) => e.inputHashBefore !== e.inputHashAfter) };
}

// ── tools ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/** The tenant's effective policy set, else the server-wide one (the same rule /ai/chat follows). */
function policiesFor(tenantId, fallback) {
  const t = require('../tenancy/tenantPolicyRegistry').getEffectivePoliciesForTenant(tenantId);
  if (t) return t;
  try { return typeof fallback === 'function' ? (fallback() || []) : []; } catch { return []; }
}

const MAX_LEAVES = 2000; const MAX_DEPTH = 64;

/**
 * Everything textual in a JSON value, found iteratively (no recursion limit to hit): string values and NUMBER values as { get, set } pairs, and object KEYS as texts of their own.
 * `overflow` is true when the value is too large or too deep to be scanned completely (more than MAX_LEAVES leaves, nesting deeper than MAX_DEPTH): the caller must not treat the
 * unscanned part as clean.
 */
function _collect(root) {
  const leaves = []; const keys = []; let overflow = false; let n = 0;
  const stack = [[{ r: root }, 'r', 0]];
  while (stack.length) {
    const [parent, key, depth] = stack.pop();
    const v = parent[key];
    if (typeof v === 'string' || typeof v === 'number') { if (++n > MAX_LEAVES) { overflow = true; break; } leaves.push([parent, key]); }
    else if (v && typeof v === 'object') {
      if (depth >= MAX_DEPTH) { overflow = true; continue; }
      for (const k of Object.keys(v)) { if (!Array.isArray(v)) { if (++n > MAX_LEAVES) { overflow = true; break; } keys.push(k); } stack.push([v, k, depth + 1]); }
      if (overflow) break;
    }
  }
  return { leaves, keys, overflow };
}

const _failClosed = (ps) => ps.some((p) => p.config.action !== 'DETECT');
const _tooLarge = (events) => ({ blocked: true, reason: 'DLP_BLOCKED', detail: 'too large or too deeply nested to scan completely', events });

/** Tool arguments: DETECT / BLOCK only (validated at policy load). The arguments are never rewritten. Keys and numbers are scanned too; a value too large to scan is refused. */
function applyToToolArgs(args, policies) {
  const ps = dlpPolicies(policies, 'tool_input');
  if (ps.length === 0) return { blocked: false, events: [] };
  const { leaves, keys, overflow } = _collect(args);
  if (overflow && _failClosed(ps)) return _tooLarge([]);
  const texts = [...leaves.map(([p, k]) => String(p[k])), ...keys];
  const r = _apply(texts, policies, 'tool_input');
  if (r.blocked) return { blocked: true, reason: r.reason, detail: r.detail, events: r.events };
  return { blocked: false, events: r.events };
}

/**
 * A tool result as returned by the MCP client ({ content: [...], structuredContent?, isError? }): returns a COPY with the transformed texts. Scanned: every text part, the text of an
 * embedded resource, every string and number inside structuredContent, and the keys of structuredContent. A KEY that holds a finding is not rewritten (it would change the shape of the
 * result): with any action other than DETECT the result is withheld. A result too large or too deep to scan completely is withheld too.
 */
function applyToToolResult(raw, policies) {
  const ps = dlpPolicies(policies, 'tool_output');
  if (ps.length === 0) return { blocked: false, raw, events: [] };
  let copy;
  try { copy = JSON.parse(JSON.stringify(raw)); } catch { return _failClosed(ps) ? { ..._tooLarge([]), raw } : { blocked: false, raw, events: [] }; }          // nesting too deep to copy
  const refs = []; let overflow = false; const keyTexts = [];
  if (Array.isArray(copy.content)) {
    for (const part of copy.content) {
      if (!part || typeof part !== 'object') continue;
      if (typeof part.text === 'string') refs.push([part, 'text']);
      if (part.resource && typeof part.resource === 'object' && typeof part.resource.text === 'string') refs.push([part.resource, 'text']);
    }
  }
  if (copy.structuredContent && typeof copy.structuredContent === 'object') {
    const c = _collect(copy.structuredContent); overflow = c.overflow; refs.push(...c.leaves); keyTexts.push(...c.keys);
  }
  if (overflow && _failClosed(ps)) return { ..._tooLarge([]), raw };
  const texts = [...refs.map(([p, k]) => String(p[k])), ...keyTexts];
  const r = _apply(texts, policies, 'tool_output');
  if (r.blocked) return { blocked: true, reason: r.reason, detail: r.detail, events: r.events, raw };
  const out = r.texts;
  // a key that changed (a finding inside a key) cannot be rewritten in place: withhold instead of delivering the original key
  for (let i = 0; i < keyTexts.length; i++) if (out[refs.length + i] !== keyTexts[i] && _failClosed(ps)) return { ..._tooLarge(r.events), detail: 'sensitive data in an object key', raw };
  refs.forEach(([p, k], i) => { p[k] = typeof p[k] === 'number' && out[i] === String(p[k]) ? p[k] : out[i]; });
  return { blocked: false, raw: copy, events: r.events, changed: r.events.some((e) => e.inputHashBefore !== e.inputHashAfter) };
}

/** Audit: one DLP_TRANSFORM chain entry per event under schema v8; otherwise a structured event (values are never logged). */
async function recordEvents(events, { requestId, tenantId } = {}) {
  let n = 0;
  for (const e of events) {
    n += 1;
    emit(e.blocked ? 'WARN' : 'INFO', 'DLP_TRANSFORM', { requestId, tenantId, ...e });
    let v8 = false;
    try { v8 = require('../audit/entryBuilder').currentSchemaVersion() >= 8; } catch { v8 = false; }
    if (!v8) continue;
    const audit = require('../audit/audit-log');
    await audit.appendMandatory({
      artifactId: `${requestId}:dlp_${e.direction === 'input' || e.direction === 'tool_input' ? 'in' : 'out'}_${n}`, entryType: 'DLP_TRANSFORM', decision: e.blocked ? 'BLOCK' : 'ALLOW', reason: `DLP_${e.action}`,
      tenantId, requestId, dlp: { rules: e.rules, action: e.action, inputHashBefore: e.inputHashBefore, inputHashAfter: e.inputHashAfter },
    }, { stage: 'DLP', maxRetries: 3, retryDelayMs: 100 });
  }
}

module.exports = { dlpPolicies, applyToBody, applyToText, textsOf, recordEvents, tokenKey, policiesFor, applyToToolArgs, applyToToolResult };
