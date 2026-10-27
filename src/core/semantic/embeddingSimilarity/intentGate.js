'use strict';

/**
 * negation/protective/reporting intent gate.
 *
 * A deterministic, rule-based POST-SCORE gate: the last step in classify()
 * has already produced a DENY. It never touches an ALLOW and never changes
 * any anchor, threshold, weight, or corpus — see config.js's threshold
 * comments, none of which move for this remediation.
 *
 * ROOT CAUSE (
 * §0): none of the four embedding gates carries any representation of
 * negation, reporting intent, or protective intent — the head and V9 linear
 * models are scored directly on the frozen MiniLM embedding (V9's 21 auxiliary
 * features are i18n/normalization/surface-ratio signals only, see
 * v9Features.js), and MiniLM sentence embeddings are dominated by topical
 * vocabulary rather than negation polarity or governing-verb framing. A
 * benign query asking to REPORT or DEFEND AGAINST a harmful topic sits close,
 * in embedding space, to a request to COMMIT it — that is the whole false
 * different items in the baseline; see PRE-REGISTRATION.md's per-item trace).
 *
 * WHY THIS IS NOT "if negation_detected: ALLOW" (explicitly forbidden — task
 * §15). Firing requires BOTH:
 *
 *   1. A FRAME match — an enumerable, closed set of governing sentence
 *      structures (an explicit first-person NEGATION OF A REQUEST, or an
 *      INTERROGATIVE reporting/defense/detection frame: "how do I report...",
 *      "how can I protect against...", "what are the warning signs of...").
 *      A bare keyword ("not", "protect", "for research") is never sufficient.
 *
 *   2. The ABSENCE of a BYPASS counter-signal — an enumerable set of
 *      operational-demand / override phrasings ("anyway", "ignore that",
 *      "instead, give me", "exactly how to", "step by step", an imperative
 *      re-request for a working artifact). Presence of any one holds the
 *      original DENY.
 *
 * The discriminating structural insight (measured on the DEV split, see
 * PRE-REGISTRATION.md and DECISION-RECORD.md): a genuine protective/negation/
 * reporting benign query is INTERROGATIVE or an explicit NEGATION OF A
 * REQUEST; an adversarial wrapper must eventually contain an IMPERATIVE
 * request for the harmful artifact to achieve its actual goal, and that
 * imperative either prevents the frame from matching in the first place
 * caught by the bypass patterns when it co-occurs with a frame in the same
 * sentence.
 *
 * ATTRIBUTION, NEVER SILENT. A firing override returns a NEW object with
 * `intentGate: true`, `intentFrame: <id>`, `originalMatchedBy: <what the
 * ensemble decided before this gate ran>` — the audit trail always shows both
 * the original denial and the reason it was overridden, never a plain ALLOW
 * indistinguishable from one the ensemble produced on its own.
 *
 * FAIL-CLOSED. Any exception in frame/bypass evaluation returns the ORIGINAL
 * result untouched — an internal error can only ever preserve a DENY, never
 * manufacture an ALLOW.
 */

// ── FRAME PATTERNS ───────────────────────────────────────────────────────────
// Each is a closed, specific governing-clause structure, not a bare keyword.
// Grouped for readability; order does not matter (first match wins, id only
// used for audit attribution).
const FRAMES = Object.freeze([
  // Explicit first-person negation of a request.
  { id: 'NEG_DONT_WANT', re: /\b(?:i|we)\s+(?:do\s*n[o']?t|does\s*n[o']?t)\s+want\b/i },
  { id: 'NEG_PLEASE_DONT_TELL', re: /\bplease\s+(?:do\s*n[o']?t|don['’]?t)\s+(?:tell|explain|show|give|provide)\b/i },
  { id: 'NEG_DONT_TELL', re: /\b(?:do\s*n[o']?t|don['’]?t)\s+(?:tell|explain|give|show|provide)\s+me\b/i },
  { id: 'NEG_NOT_A_REQUEST', re: /\bthis\s+is\s*n[o']?t\s+a\s+request\s+for\b/i },
  { id: 'NEG_NOT_ASKING', re: /\b(?:i['’]?m|i\s+am)\s+not\s+asking\s+(?:for|you\s+to)\b/i },
  { id: 'NEG_DOUBLE', re: /\b(?:not\s+that\s+i\s+don['’]?t|wouldn['’]?t\s+say\s+i['’]?m\s+uninterested)\b/i },
  // Interrogative reporting-to-authority intent.
  { id: 'REPORT_HOW', re: /\b(?:how|where)\s+(?:do|can|should)\s+i\s+(?:report|flag|document|file\s+a\s+(?:whistleblower\s+)?complaint)\b/i },
  { id: 'REPORT_ANON', re: /\bhow\s+can\s+i\s+anonymously\s+report\b/i },
  // Interrogative protective/defensive/detection intent.
  { id: 'DEFEND_HOW_ORG', re: /\bhow\s+(?:do|can|does)\s+(?:organi[sz]ations?|companies|banks|i|we|a\s+small\s+business|parents)\s+(?:defend\s+against|protect)\b/i },
  { id: 'DEFEND_CAN_I_PROTECT', re: /\bhow\s+can\s+i\s+protect\b/i },
  { id: 'DEFEND_SAFEGUARDS', re: /\bwhat\s+safeguards?\s+prevent\b/i },
  { id: 'DEFEND_STEPS_PREVENT', re: /\bwhat\s+steps\s+can\b.*\bprevent\b/i },
  { id: 'DEFEND_DETECT', re: /\bhow\s+(?:can|do)\s+(?:i|banks|organi[sz]ations)\s+detect\b/i },
  { id: 'DEFEND_LOOK_FOR', re: /\bwhat\s+should\s+i\s+look\s+for\s+to\s+identify\b/i },
  { id: 'DEFEND_WARNING_SIGNS', re: /\bwhat\s+(?:are|would\s+be)\s+the\s+warning\s+signs\b/i },
  { id: 'DEFEND_DIAGNOSED', re: /\bhow\s+is\s+.+\s+diagnosed\s+clinically\b/i },
  { id: 'DEFEND_MEDIA_GUIDELINES', re: /\bmedia\s+guidelines\s+for\s+reporting\s+responsibly\b/i },
  { id: 'DEFEND_TRAIN_RECOGNIZE', re: /\btrain\s+(?:staff|employees|people)\s+to\s+recogni[sz]e\b/i },
  { id: 'DEFEND_HOW_TRAIN', re: /\bhow\s+should\s+.*\btrain\b.*\brecogni[sz]e\b/i },
  { id: 'DEFEND_DETECTION_RULE', re: /\b(?:write|build|create)\s+a\s+detection\s+rule\b|\bflags?\s+messages?\s+matching\b/i },
  { id: 'DEFEND_TIGHTEN_PRIVACY', re: /\bhow\s+can\s+i\s+tighten\b.*\bprivacy\b/i },
]);

// ── BYPASS COUNTER-SIGNALS ───────────────────────────────────────────────────
// Presence of ANY of these disables the override, even when a frame matched.
const BYPASS = Object.freeze([
  { id: 'BYPASS_OVERRIDE', re: /\b(?:anyway|ignore\s+(?:that|this|the\s+above)|skip\s+that|disregard)\b/i },
  { id: 'BYPASS_INSTEAD_IMPERATIVE', re: /\binstead[,]?\s+(?:give|tell|show|provide)\s+me\b/i },
  { id: 'BYPASS_OPERATIONAL_DEMAND', re: /\b(?:exact(?:ly)?\s+(?:steps|command|wording|quantities|code|operational)|step[\s-]?by[\s-]?step|full\s+operational\s+detail|working\s+(?:exploit|payload|sample)|literal\s+command|exactly\s+how\s+to)\b/i },
  { id: 'BYPASS_ARTIFACT_IMPERATIVE', re: /\b(?:actually\s+)?(?:give|write|provide|develop|build|create)\s+(?:me\s+)?(?:a|an|the)\s+(?:working|real|actual|fully\s+operational|convincing)\b/i },
  { id: 'BYPASS_BUT_FIRST', re: /\bbut\s+first\b/i },
  // a protective FRAME in one sentence must not launder an imperative request for the harmful artifact in
  // the next ("How can I protect my family? Give me instructions for building a pipe bomb"). A second-person imperative aimed at ME
  // ("give/tell/show/teach/send me <how | instructions | steps | a guide | ...>") or a bare "explain/describe how to <make/build>" is a
  // request for an operational artifact, which is exactly what the gate's header says an adversarial wrapper must eventually contain.
  // `negatable` patterns ignore a match that is itself negated within its own clause ("please don't tell me ...", "I do not want
  // instructions for ...") — those are the NEG_* frames' own wording, not a demand.
  { id: 'BYPASS_IMPERATIVE_REQUEST_ME', negatable: true, re: /\b(?:give|tell|show|teach|send|get)\s+me\s+(?:the\s+|some\s+|a\s+|an\s+|your\s+|any\s+)?(?:\w+\s+){0,2}?(?:instructions?|steps?|guide|tutorial|recipe|walk-?through|blueprint|method|way|details?|how\b)/i },
  { id: 'BYPASS_INSTRUCTIONS_FOR', negatable: true, re: /\binstructions\s+(?:for|on|to)\s+(?:building|making|creating|synthesi[sz]ing|assembling|manufacturing|producing|cooking|how\b)/i },
  { id: 'BYPASS_EXPLAIN_HOW_TO_MAKE', negatable: true, re: /\b(?:explain|describe|outline|walk\s+me\s+through)\s+(?:to\s+me\s+)?how\s+to\s+(?:build|make|create|synthesi[sz]e|assemble|manufacture|produce|cook|construct)\b/i },
  { id: 'BYPASS_REPLICATE', re: /\b(?:replicate|reproduce)\s+it\s+myself\b|\bso\s+i\s+can\s+(?:replicate|reproduce|do\s+it\s+myself|try\s+it\s+myself)\b/i },
]);

// A match is "negated" when a negator precedes it in the same clause (no sentence/clause punctuation in between).
// (verification): the negator must sit directly before the match: at most three plain words between them, none of them a
// conjunction, and no punctuation at all. A comma used to carry a negation across clauses ("I am not a criminal, give me ..."
// or "Don't hesitate, give me ..."), which switched the negatable BYPASS patterns off and let the protective frame launder the request.
const _NEGATOR_BEFORE = /\b(?:do\s*n[o']?t|don['’]?t|does\s*n[o']?t|not|never|no)\b(?:\s+(?!(?:and|but|then|so|or|also|now|yet|because|since)\b)[\w'’-]+){0,3}\s*$/i;

function _matchesUnnegated(re, text) {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m;
  while ((m = g.exec(text)) !== null) {
    const prefix = text.slice(Math.max(0, m.index - 60), m.index);
    if (!_NEGATOR_BEFORE.test(prefix)) return true;
    if (m[0].length === 0) g.lastIndex++;
  }
  return false;
}

function _matchFirst(patterns, text) {
  for (const p of patterns) {
    if (p.negatable ? _matchesUnnegated(p.re, text) : p.re.test(text)) return p.id;
  }
  return null;
}

/**
 * @param {object} result the ensemble's result object (from _classifyWindow /
 *   _maybeFifthGate / _maybeSixthGate) — read-only, never mutated
 * @param {string} text the window's own text the ensemble scored
 * @returns {object} `result` unchanged, or a new frozen object with the
 *   decision overridden to ALLOW and full attribution fields set
 */
function maybeOverride(result, text) {
  if (!result || result.decision !== 'DENY') return result;
  if (typeof text !== 'string' || text.length === 0) return result;

  try {
    const frame = _matchFirst(FRAMES, text);
    if (!frame) return result;

    const bypass = _matchFirst(BYPASS, text);
    if (bypass) return result;

    return Object.freeze({
      ...result,
      decision: 'ALLOW',
      intentGate: true,
      intentFrame: frame,
      originalMatchedBy: result.matchedBy,
    });
  } catch {
    // Fail-closed: any error in frame/bypass evaluation preserves the
    // original (DENY) result untouched. This code path can never turn an
    // error into an ALLOW.
    return result;
  }
}

module.exports = { maybeOverride, FRAMES, BYPASS };
