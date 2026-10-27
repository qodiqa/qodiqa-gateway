'use strict';

const { normalize, normalizeCased, scoreSignals } = require('../textSignals');

/**
 * Common classifier interface used across every module under
 * classifier/classifiers/:
 *
 *   classify(context) -> { id, confidence, severity, reason, evidence } | null
 *
 * `null` means "this classifier found nothing" — it is not itself a
 * decision. The Semantic Policy Engine (../index.js) aggregates whatever
 * non-null results all registered classifiers return; a single classifier
 * never decides ALLOW/WARN/REVIEW/DENY on its own.
 *
 * defineClassifier() is the standard way to build one: supply metadata plus
 * a weighted signal set, and get a fully-formed classifier object back. This
 * keeps every classifier file purely declarative (metadata + signals), with
 * all normalization/scoring logic centralized in textSignals.js — so adding
 * classifier #12, #50, or #200 never requires touching the scoring engine.
 *
 * A classifier is not required to use this factory — any object shaped like
 * { id, classify(context) } is valid (see registry/classifierRegistry.js) —
 * but it is the recommended default and is what every bundled classifier
 * uses.
 */
function defineClassifier(def) {
  if (!def || typeof def.id !== 'string' || !def.id) {
    throw new Error('defineClassifier: "id" is required');
  }
  if (typeof def.reason !== 'string' || !def.reason) {
    throw new Error(`defineClassifier(${def.id}): "reason" is required`);
  }
  if (typeof def.severity !== 'string' || !def.severity) {
    throw new Error(`defineClassifier(${def.id}): "severity" is required`);
  }
  if (!Array.isArray(def.signals) || !def.signals.length) {
    throw new Error(`defineClassifier(${def.id}): "signals" must be a non-empty array`);
  }

  return Object.freeze({
    id: def.id,
    reason: def.reason,
    severity: def.severity,

    classify(context) {
      // Prefer the engine's single, pre-computed normalization pass
      // (ctx.normalizedPrompt, set once per request in index.js) over
      // recomputing it here on every classifier — follow-up remediation
      // requirement #5/#7 (one normalization stage before every classifier,
      // not N recomputations of the same text). Falls back to computing it
      // directly when absent so classifiers remain independently testable
      // via classifier.classify({ prompt }) and custom classifiers
      // registered through registerClassifier() (which may not know about
      // normalizedPrompt) keep working unmodified.
      const text = (context && typeof context.normalizedPrompt === 'string')
        ? context.normalizedPrompt
        : normalize(context && context.prompt);
      if (!text) return null;

      let result = scoreSignals(text, def.signals);

      // Optional structural refinement — e.g. proximity/co-occurrence
      // bonuses between signal categories. Purely deterministic; receives
      // only the already-normalized text and the base score, never the
      // raw context, so refinement logic can't accidentally depend on
      // anything outside the text itself.
      //
      // adds a THIRD argument: the same text with letter case
      // preserved, for the narrow set of refinements that need case shape
      // (camelCase identifiers). Appended, not substituted — every existing
      // refine(text, result) implementation keeps working untouched, and a
      // refinement that ignores the third argument behaves exactly as before.
      // Same fallback rule as `text` above so classifiers stay independently
      // testable via classifier.classify({ prompt }).
      if (typeof def.refine === 'function') {
        const casedText = (context && typeof context.casePreservedPrompt === 'string')
          ? context.casePreservedPrompt
          : normalizeCased(context && context.prompt);
        const refined = def.refine(text, result, casedText);
        if (refined) result = refined;
      }

      if (result.confidence <= 0) return null;

      return {
        id: def.id,
        confidence: Number(result.confidence.toFixed(4)),
        severity: def.severity,
        reason: def.reason,
        evidence: {
          // Only signal tags/weights are retained — never raw matched
          // substrings — so semantic evidence never carries verbatim
          // prompt content into the audit trail, consistent with the
          // rest of QODIQA's audit model (hashes, not payloads).
          matchedSignals: result.matched.map((m) => ({ tag: m.tag, weight: m.weight })),
        },
      };
    },
  });
}

module.exports = { defineClassifier };
