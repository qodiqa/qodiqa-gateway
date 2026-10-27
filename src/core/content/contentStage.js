'use strict';

/**
 * The content-rule stage: applies the CONTENT_RULE rules (services/policy/evaluators/contentRule.js) of the tenant's policy set to the text of a request or answer.
 *
 *   check(texts, policies, direction, { model, purpose }) -> { blocked, reason?, hits: [{ ruleId, action, items: [ids], score, threshold }] }
 *
 * Text is normalised before matching (NFKC; format characters, combining marks and control characters removed; whitespace collapsed to one space), so a word split by an invisible
 * character, written in fullwidth form, or spread over several spaces is still found. Word and phrase items are compared case-insensitively unless the item says otherwise; a `word` must
 * be bounded by non-letters, a `phrase` is a substring. Regular expressions run on the linear-time engine. A rule fires when the weights of the DISTINCT items that matched reach the
 * threshold that applies to the request's model and declared purpose. Only item ids leave this module - never the matched text.
 *
 * Fail closed: text the regex engine cannot scan completely (longer than its bound), or any unexpected failure, refuses the request when the rule's action is BLOCK
 * (CONTENT_RULE_UNAVAILABLE) and is merely reported for DETECT.
 */

const { emit } = require('../../../services/logger');

const rules = (policies, direction) => (policies || []).filter((p) => p && p.type === 'CONTENT_RULE' && p.enabled === true && p.config && (p.config.direction === direction || p.config.direction === 'both'))
  .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0) || String(a.id).localeCompare(String(b.id)));

// F8V-10: besides format characters, combining marks and controls, the blank-looking letters (Hangul fillers, Braille blank, Mongolian vowel separator) are removed, and the text is
// decomposed (NFKD) before the combining marks go, so an accented letter matches its plain form.
const INVISIBLE = /[\p{Cf}\p{Mn}\p{Me}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u{115f}\u{1160}\u{3164}\u{ffa0}\u{2800}\u{180e}]/gu;
function normalise(text) { return text.normalize('NFKD').replace(INVISIBLE, '').replace(/\s+/g, ' '); }

// F8V-09: the regex engine is linear per pattern, but many patterns over a long text add up: the total (states x characters) scanned in one check is capped, and over the cap the check
// fails closed like any text the engine cannot scan completely.
const MAX_REGEX_WORK = 10_000_000;

const isLetter = (ch) => /[\p{L}\p{N}_]/u.test(ch);
function indexOfWord(hay, needle) {
  let from = 0;
  for (;;) {
    const i = hay.indexOf(needle, from); if (i < 0) return false;
    const prev = i === 0 ? null : [...hay.slice(Math.max(0, i - 2), i)].pop();
    const nextIdx = i + needle.length; const next = nextIdx >= hay.length ? null : String.fromCodePoint(hay.codePointAt(nextIdx));
    if ((prev === null || !isLetter(prev)) && (next === null || !isLetter(next))) return true;
    from = i + 1;
  }
}

function inScope(list, value) { return list === undefined || value === undefined || value === null || list.includes(value); }

function thresholdFor(cfg, model, purpose) {
  for (const t of cfg.thresholds || []) {
    const modelOk = t.models === undefined || (typeof model === 'string' && t.models.includes(model));
    const purposeOk = t.purposes === undefined || (typeof purpose === 'string' && t.purposes.includes(purpose));
    if (modelOk && purposeOk) return t.threshold;
  }
  return cfg._threshold || cfg.threshold || 1;
}

function check(texts, policies, direction, { model, purpose } = {}) {
  const active = rules(policies, direction).filter((p) => inScope(p.config.scope && p.config.scope.models, model) && inScope(p.config.scope && p.config.scope.purposes, purpose));
  if (active.length === 0) return { blocked: false, hits: [] };
  const hits = []; const joined = texts.map(normalise); let work = 0;
  for (const p of active) {
    const cfg = p.config; let score = 0; const matched = []; let unavailable = false;
    try {
      cfg.items.forEach((it, idx) => {
        const ci = it.caseInsensitive !== false;
        const needle = it.kind === 'regex' ? null : (ci ? normalise(it.value).toLowerCase() : normalise(it.value));
        const hit = joined.some((t) => {
          if (it.kind === 'regex') {
            work += cfg._compiled[idx].states * t.length;
            if (work > MAX_REGEX_WORK) throw new Error('regex work cap exceeded');
            return cfg._compiled[idx].test(t);
          }
          const hay = ci ? t.toLowerCase() : t;
          return it.kind === 'word' ? indexOfWord(hay, needle) : hay.includes(needle);
        });
        if (hit) { score += it.weight || 1; matched.push(it.id); }
      });
    } catch (e) { unavailable = true; emit('WARN', 'CONTENT_RULE_UNSCANNED', { ruleId: p.id, error: String(e && e.message).slice(0, 120) }); }
    if (unavailable) { if (cfg.action === 'BLOCK') return { blocked: true, reason: 'CONTENT_RULE_UNAVAILABLE', hits: [{ ruleId: p.id, action: cfg.action, items: [], score, threshold: thresholdFor(cfg, model, purpose) }] }; continue; }
    const threshold = thresholdFor(cfg, model, purpose);
    if (score >= threshold && matched.length > 0) {
      const hit = { ruleId: p.id, action: cfg.action, items: matched, score, threshold };
      hits.push(hit);
      emit(cfg.action === 'BLOCK' ? 'WARN' : 'INFO', 'CONTENT_RULE_HIT', { ruleId: p.id, direction, action: cfg.action, items: matched, score, threshold });
      if (cfg.action === 'BLOCK') return { blocked: true, reason: 'CONTENT_RULE_BLOCKED', hits };
    }
  }
  return { blocked: false, hits };
}

module.exports = { check, normalise, rules };
