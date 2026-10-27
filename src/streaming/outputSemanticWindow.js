'use strict';

/**
 * Output-side semantic classification for streaming responses (
 * re-architected by).
 *
 * Reuses the exact same engines the non-streaming path uses
 * (src/core/semantic/index.js's runSemanticPolicyEngine() and
 * src/core/semantic/embeddingGate.js's checkText()) — no duplicate
 * classifiers, confidence logic, or evidence model. This module owns only the
 * bounded, incremental bookkeeping needed to apply those engines to a growing
 * stream of text without buffering the whole response, and — —
 * the RELEASE ORDERING that guarantees nothing reaches the client ahead of
 * its own check.
 *
 * ══ check-then-release, not release-then-check ═══════════════════
 *
 *`evaluate(delta)` combined two independently-cadenced
 * verdicts and the CALLER (streamEnforcer.js) forwarded `delta` unconditionally
 * whenever the combined verdict was non-blocking. The embedding half of that
 * verdict is only recomputed every `EMBEDDING_INTERVAL_CHARS` accumulated
 * characters — between recomputations, chunks were forwarded under a STALE
 * verdict that predates the content it was being applied to. This is a
 * release-before-check ordering defect (master control P1): up to
 * `EMBEDDING_INTERVAL_CHARS - 1` characters, or an entire completion shorter
 * than that, could reach the client before the embedding layer — which
 * carries essentially all measured detection — had ever evaluated
 * them at all. Measured baseline: 378 characters forwarded before the first
 * embedding check ever ran; a 152-character adversarial completion delivered
 * in full, caught only by the post-stream recheck after every byte was
 * already on the wire (E-0058 S4, E-0055 S1).
 *
 * The fix keeps the IDENTICAL cadence and the IDENTICAL number of embedding
 * calls (no throughput regression — see DECISION-RECORD.md §14) and only
 * reorders WHEN release happens relative to the check that is supposed to
 * gate it:
 *
 *   Keyword engine  — unchanged. Interval=1 (every call), synchronous,
 *                      cannot hang. A block discards the entire pending
 *                      buffer (see below), not just the current delta.
 *   Embedding gate  — text is now accumulated into `pendingBuffer` (bounded
 *                      at EMBEDDING_INTERVAL_CHARS, same value as before) and
 *                      NEVER reported as released until the check for that
 *                      exact buffer has run and passed. `evaluate()` returns
 *                      a `released` string — possibly empty — which is the
 *                      ONLY text the caller may forward. Content shorter than
 *                      one interval is held until either (a) it grows to fill
 *                      one, or (b) the stream ends, at which point the
 *                      mandatory `evaluateFinal()` check gates it exactly like
 *                      any other buffer-full — closing both baseline cases.
 *
 * Maximum buffered (held, unreleased) characters at any time: EMBEDDING_INTERVAL_CHARS
 * (default 400) — identical order of magnitude to the pre-existing
 * `embeddingTrailingText` bound; nothing new is held longer or in greater
 * quantity than before. See DECISION-RECORD.md §13.
 *
 * A keyword or embedding DENY, a detector timeout/error, a client
 * disconnect, or a provider error all discard the pending buffer via the
 * same code path (`_discard()` / `discardPending()`) — none of them can ever
 * cause `released` to be non-empty for content that has not itself passed a
 * fresh check. See
 *
 * Bounded memory (all four windows):
 *   `keywordTrailing`   ≤ WINDOW_SIZE_CHARS       (unchanged, keyword scoring context)
 *   `pendingBuffer`     ≤ EMBEDDING_INTERVAL_CHARS (NEW — held, unreleased text)
 *   `embeddingTrailing` ≤ WINDOW_SIZE_CHARS       (unchanged, embedding scoring context —
 *                                                   a superset of pendingBuffer, so
 *                                                   cross-window attacks stay visible)
 *   `fullText`          unbounded (unchanged — evaluateFinal()'s full-artifact check;
 *                                   embeddingSimilarity.classify() internally windows
 *                                   arbitrarily long text into <=400-char slices, see
 *                                   embeddingSimilarity/index.js's MAX_CHARS_PER_WINDOW)
 *
 * Detector timeout: every embeddingGate.checkText() call is
 * wrapped in a bounded race against QODIQA_STREAM_SEMANTIC_EMBEDDING_TIMEOUT_MS
 * (default 5000ms). On timeout the wrapper resolves to a DENY-shaped verdict
 * — the pending buffer is discarded, never released. The keyword engine is
 * pure synchronous arithmetic and cannot hang; no timeout wrapper is used for it.
 *
 * "Minimum confidence" / "abort threshold" are still NOT separate streaming
 * knobs — they are the shared engine's own
 * QODIQA_SEMANTIC_THRESHOLD_(WARN|REVIEW|DENY) / *_BLOCKS config
 * (policies/semanticPolicy.js), applied identically to request and response
 * text. does not introduce a second, looser (or stricter) gate.
 */

const { runSemanticPolicyEngine } = require('../core/semantic');
const embeddingGate = require('../core/semantic/embeddingGate');

function _num(envVar, fallback) {
  const v = parseInt(process.env[envVar], 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

const WINDOW_SIZE_CHARS = _num('QODIQA_STREAM_SEMANTIC_WINDOW_CHARS', 4000);
const INTERVAL_CHARS    = _num('QODIQA_STREAM_SEMANTIC_INTERVAL_CHARS', 1);
// this value is now BOTH the embedding check cadence AND the
// maximum pre-release buffer bound — check-then-release means those are the
// same operation. Unchanged default and unchanged semantics for an operator
// who already tuned this env var earlier.
const EMBEDDING_INTERVAL_CHARS = _num('QODIQA_STREAM_SEMANTIC_EMBEDDING_INTERVAL_CHARS', 400);
// (S3): bounded wait on every embeddingGate.checkText() call. A
// detector that does not resolve within this budget is treated exactly like
// one that returned DENY — the buffer is discarded, never released.
const EMBEDDING_TIMEOUT_MS = _num('QODIQA_STREAM_SEMANTIC_EMBEDDING_TIMEOUT_MS', 5000);
// the same output classification cap as the non-stream path.
const { OUTPUT_MAX_CHARS } = require('../core/semantic/classificationBudget');

const ALLOW_VERDICT = Object.freeze({
  blocks: false, decision: 'ALLOW', reason: null, evidence: null, released: '',
});

function _denyVerdict(decision, reason, evidence) {
  return Object.freeze({ blocks: true, decision: decision || 'DENY', reason: reason || null, evidence: evidence || null, released: '' });
}

function _allowVerdict(evidence, released) {
  return Object.freeze({ blocks: false, decision: 'ALLOW', reason: null, evidence: evidence || null, released: released || '' });
}

/**
 * Runs `checkTextFn()` with a bounded timeout. On timeout, resolves (never
 * rejects) to a DENY-shaped result carrying failureReason EMBEDDING_TIMEOUT —
 * matching the shape embeddingGate.checkText()'s own internal fail-closed
 * paths already use, so callers do not need a second failure vocabulary.
 */
function _withTimeout(promise, ms) {
  let timer = null;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      resolve({
        blocks: true, decision: 'DENY', reason: 'EMBEDDING_TIMEOUT',
        evidence: null, engineStatus: 'UNAVAILABLE', failureReason: 'EMBEDDING_TIMEOUT',
      });
    }, ms);
    if (timer.unref) timer.unref();
  });
  // (S2): a rejecting promise (the detector throwing/erroring) must
  // fail closed exactly like a timeout, never propagate as an uncaught
  // rejection that could bypass this module's DENY-shaped contract.
  const guarded = promise.catch(() => ({
    blocks: true, decision: 'DENY', reason: 'EMBEDDING_ERROR',
    evidence: null, engineStatus: 'UNAVAILABLE', failureReason: 'EMBEDDING_ERROR',
  }));
  return Promise.race([guarded, timeout]).finally(() => clearTimeout(timer));
}

/**
 * @param {{ requestId: string|null, tenantId: string|null, provider: string|null }} ctx
 * @returns {{
 *   evaluate: (deltaText: string) => Promise<{blocks:boolean, decision:string, reason:string|null, evidence:object|null, released:string}>,
 *   evaluateFinal: () => Promise<{blocks:boolean, decision:string, reason:string|null, evidence:object|null, released:string}>,
 *   discardPending: () => void,
 *   pendingLength: () => number,
 * }}
 */
function createOutputSemanticWindow({ requestId, tenantId, provider }) {
  // one embedding memo per stream. Every trailing-span check below still classifies exactly the
  // same text as before; windows this stream already embedded reuse their (identical) vectors instead of being
  // re-embedded. See src/core/semantic/embeddingSimilarity/embedMemo.js.
  const embedMemo = require('../core/semantic/embeddingSimilarity/embedMemo');
  const memo = embedMemo.create();
  const checkMemo = (text) => embedMemo.run(memo, () => embeddingGate.checkText(text, { requestId, tenantId, provider, surface: 'RESPONSE_STREAM' }));
  let keywordTrailing = '';
  // sinceLastKeywordPass is retained even though the default interval is 1
  // (every call) — an operator raising QODIQA_STREAM_SEMANTIC_INTERVAL_CHARS
  // still gets the documented, deterministic degradation described in
  // docs/architecture/streaming.md §15.3 (unchanged).
  let sinceLastKeywordPass = 0;
  let lastKeywordVerdict   = ALLOW_VERDICT;

  // pendingBuffer is text that has been classified as not YET known
  // unsafe but has NOT been released to the caller. It is cleared (never
  // flushed) on every DENY/timeout/error/cancellation path.
  let pendingBuffer      = '';
  let embeddingTrailing  = '';
  let fullText           = '';

  function _discard() { pendingBuffer = ''; }

  async function evaluate(deltaText) {
    const text = typeof deltaText === 'string' ? deltaText : '';
    if (text.length === 0) return _allowVerdict(null, '');

    // once the stream's output would exceed the classification cap, the pending buffer is
    // discarded and the stream is denied at this point — nothing past the cap is ever released.
    if (fullText.length + text.length > OUTPUT_MAX_CHARS) {
      _discard();
      return _denyVerdict('DENY', 'OUTPUT_TOO_LARGE', { surface: 'RESPONSE_STREAM', outputChars: fullText.length + text.length, maxChars: OUTPUT_MAX_CHARS });
    }

    // ── 1. Keyword engine — unchanged cadence/cost, evaluated first ─────────
    keywordTrailing = (keywordTrailing + text).slice(-WINDOW_SIZE_CHARS);
    sinceLastKeywordPass += text.length;
    if (sinceLastKeywordPass >= INTERVAL_CHARS) {
      sinceLastKeywordPass = 0;
      lastKeywordVerdict = runSemanticPolicyEngine({
        prompt: keywordTrailing, provider: provider || null, tenantId: tenantId || null,
        requestId: requestId || null, surface: 'RESPONSE_STREAM',
      });
    }
    if (lastKeywordVerdict.blocks) {
      // A keyword block discards the WHOLE pending buffer, not just this
      // delta — see DECISION-RECORD.md §8 for why this is an accepted,
      // strictly-safer trade-off rather than a bug.
      _discard();
      return _denyVerdict(lastKeywordVerdict.decision, lastKeywordVerdict.reason, lastKeywordVerdict.evidence);
    }

    // ── 2. Accumulate into the PENDING (unreleased) buffer ──────────────────
    pendingBuffer += text;
    embeddingTrailing = (embeddingTrailing + text).slice(-WINDOW_SIZE_CHARS);
    fullText += text;

    if (pendingBuffer.length < EMBEDDING_INTERVAL_CHARS) {
      // Held — not yet enough accumulated to justify (or require) a check.
      // Nothing is released this call. This is the state that used to leak.
      return _allowVerdict(null, '');
    }

    // ── 3. Buffer is full: check BEFORE release ─────────────────────────────
    const embVerdict = await _withTimeout(
      checkMemo(embeddingTrailing),
      EMBEDDING_TIMEOUT_MS,
    );
    if (embVerdict.blocks) {
      _discard();
      return _denyVerdict(embVerdict.decision, embVerdict.reason, embVerdict.evidence);
    }
    const released = pendingBuffer;
    pendingBuffer = '';
    return _allowVerdict(embVerdict.evidence, released);
  }

  /**
   * Mandatory, unconditional end-of-stream check — called once after the
   * provider generator exhausts NORMALLY (streamEnforcer.js). Runs over the
   * COMPLETE accumulated text (not a trailing window), exactly as before
   *. Its effect now DIFFERS by case:
   *   - If pendingBuffer is non-empty (the response ended before filling one
   *     embedding interval — the 152/378-char baseline shape): this check
   *     GATES that buffer's release for the first time. A DENY here means
   *     ZERO characters of that tail were ever released — closing both
   *     baseline cases.
   *   - If pendingBuffer is already empty (everything was released via
   *     earlier interval-based passes): this call is a defense-in-depth,
   * whole-artifact audit check identical in spirit to's original
   *     "audit-truth over suppression" rationale — it can correct the
   *     terminal event/audit record but cannot un-release content already
   *     on the wire (SSE has no recall; unchanged physical limitation).
   */
  async function evaluateFinal() {
    if (!fullText) return _allowVerdict(null, '');
    const verdict = await _withTimeout(
      checkMemo(fullText),
      EMBEDDING_TIMEOUT_MS,
    );
    if (verdict.blocks) {
      _discard();
      return _denyVerdict(verdict.decision, verdict.reason, verdict.evidence);
    }
    const released = pendingBuffer;
    pendingBuffer = '';
    return _allowVerdict(verdict.evidence, released);
  }

  /**
   * explicit discard for cancellation/error paths in streamEnforcer.js
   * so no caller can accidentally reference (or worse, release) a stale
   * pending buffer after a terminal, non-ALLOW outcome. Idempotent.
   */
  function discardPending() { _discard(); }

  /** For buffer-safety test/metrics — never exceeds EMBEDDING_INTERVAL_CHARS. */
  function pendingLength() { return pendingBuffer.length; }

  /** (step 7): characters of output this stream classified (for the tenant's classification budget). */
  function classifiedChars() { return fullText.length; }

  /** memo effectiveness for this stream (hits = embeddings not recomputed). */
  function memoStats() { return { hits: memo.hits, misses: memo.misses, minilmEntries: memo.minilm.size, ft3Entries: memo.ft3.size }; }

  return { evaluate, evaluateFinal, discardPending, pendingLength, memoStats, classifiedChars };
}

module.exports = {
  createOutputSemanticWindow, WINDOW_SIZE_CHARS, INTERVAL_CHARS, EMBEDDING_INTERVAL_CHARS, EMBEDDING_TIMEOUT_MS,
};
