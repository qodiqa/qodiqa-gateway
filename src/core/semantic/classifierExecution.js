'use strict';

const { SEVERITY } = require('./reasons');
const { monoNowMs } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

const VALID_SEVERITIES = new Set(Object.values(SEVERITY));

/**
 * Validates a classifier's raw return value against the
 * { id, confidence, severity, reason, evidence } contract documented in
 * classifier/baseClassifier.js. Does not validate null/undefined ("no
 * finding") — callers must check for that separately, since it is a valid,
 * successful outcome, not a validation subject.
 *
 * remediation requirement #8: malformed output, missing required
 * fields, invalid confidence, NaN values, impossible scores, and schema
 * violations must all be rejected as classifier failure — never silently
 * passed through to the aggregator.
 *
 * @param {*} result
 * @returns {boolean}
 */
function isValidClassifierOutput(result) {
  if (!result || typeof result !== 'object') return false;
  if (typeof result.id !== 'string' || !result.id) return false;
  if (typeof result.reason !== 'string' || !result.reason) return false;
  if (typeof result.severity !== 'string' || !VALID_SEVERITIES.has(result.severity)) return false;
  if (typeof result.confidence !== 'number' || !Number.isFinite(result.confidence)) return false;
  if (result.confidence < 0 || result.confidence > 1) return false;
  return true;
}

/**
 * Runs every classifier against ctx, isolating each one so a single
 * throwing, slow, or malformed classifier can never crash the request or
 * corrupt the results passed to the aggregator.
 *
 * Every classifier falls into exactly one outcome:
 *   - threw                         -> failed
 *   - exceeded policy.classifierTimeoutMs -> timedOut (result discarded,
 *     even though — being synchronous — it did already return; this cannot
 *     preempt a pathological classifier, only detect and refuse to trust it,
 *     see policies/semanticPolicy.js)
 *   - returned null/undefined       -> succeeded, no result ("found nothing"
 *     is a legitimate, successful outcome per the classifier contract)
 *   - returned a malformed object   -> invalidOutput
 *   - returned a well-formed object -> succeeded, contributes to results[]
 *
 * @param {Array<{id:string, classify:Function}>} classifiers
 * @param {object} ctx
 * @param {{classifierTimeoutMs?: number}} policy
 * @returns {{
 *   results: Array<object>,
 *   executed: number,
 *   succeeded: number,
 *   failed: number,
 *   timedOut: number,
 *   invalidOutput: number,
 *   failures: Array<{classifierId:string, category:string, message:string|null}>,
 * }}
 */
function executeClassifiers(classifiers, ctx, policy) {
  const timeoutMs = (policy && policy.classifierTimeoutMs) || 0;
  const outcome = {
    results:       [],
    executed:      0,
    succeeded:     0,
    failed:        0,
    timedOut:      0,
    invalidOutput: 0,
    failures:      [],
  };

  for (const classifier of classifiers) {
    outcome.executed += 1;
    const startedAt = monoNowMs(); // monotonic (same-process)
    let raw;

    try {
      raw = classifier.classify(ctx);
    } catch (err) {
      outcome.failed += 1;
      outcome.failures.push({
        classifierId: classifier.id,
        category:     'EXCEPTION',
        message:      (err && err.message) || 'unknown error',
      });
      continue;
    }

    const durationMs = monoNowMs() - startedAt; // monotonic (same-process)
    if (timeoutMs > 0 && durationMs > timeoutMs) {
      outcome.timedOut += 1;
      outcome.failures.push({
        classifierId: classifier.id,
        category:     'TIMEOUT',
        message:      `exceeded ${timeoutMs}ms budget (took ${durationMs}ms)`,
      });
      continue;
    }

    if (raw === null || raw === undefined) {
      outcome.succeeded += 1;
      continue;
    }

    if (!isValidClassifierOutput(raw)) {
      outcome.invalidOutput += 1;
      outcome.failures.push({
        classifierId: classifier.id,
        category:     'INVALID_OUTPUT',
        message:      null, // never log the malformed payload itself
      });
      continue;
    }

    outcome.succeeded += 1;
    outcome.results.push(raw);
  }

  return outcome;
}

module.exports = { executeClassifiers, isValidClassifierOutput };
