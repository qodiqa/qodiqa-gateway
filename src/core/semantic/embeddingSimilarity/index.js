'use strict';

/**
 * SEM-C — embedding-similarity classifier (B1 backend: ONNX MiniLM, locked in
 *
 * Reached from the decision path via ../embeddingGate.js, which is awaited by
 * aiChat.js's _runSemanticCheck()/_runOutputSemanticCheck() and by
 * streamEnforcer/outputSemanticWindow — always AFTER the keyword engine, and
 * only when the keyword engine did not already block. That indirection exists
 * because the classifier registry's loop is synchronous
 * (../classifierExecution.js) while ONNX inference is unavoidably async; the
 * gate is the async-tolerant seam, so this module is never registered through
 * registerClassifier().
 *
 * FOUR GATES, ONE EMBEDDING (· B-3, then B-2 (a'), then B-2 (b)'s
 * union). A window is DENIED if any of them fires:
 *
 *     DENY  iff  (EXISTS a: cos(v, a) >= threshold(a.family))
 *                OR  (headB3(v)   > T_head)
 *                OR  (v9(v, text) > T_v9)
 *                OR  (v5(v)       > T_v5)
 *
 * All four read the SAME embedding `v`, computed once per window, so the three
 * model gates cost two 384-dim dot products and one 405-dim one (plus V9's 21
 * cheap signals) rather than three extra model passes. Measured per window:
 *
 * provable rather than hoped for: on a set where every component is
 *
 * V5-only is 3, and 6 are shared — so the union banks 12 where either alone
 * which only direct counting revealed.
 *
 * See config.js's HEAD_SCORE_THRESHOLD, V9_SCORE_THRESHOLD and
 * V5_SCORE_THRESHOLD blocks for each threshold's provenance,
 * and
 * for the integrated measurements.
 *
 * Fail-closed (D5), mirroring the precedent in ../index.js's
 * _denyEngineFailure()/outermost try/catch: any failure to load the model,
 * load/embed the anchor set, run inference, or score a result returns a
 * structured DENY — it is never allowed to throw, and never silently
 * resolves to ALLOW just because inspection could not complete.
 *
 * Deliberately no PER-REQUEST logger/metrics emission here (unlike
 * ../index.js's _denyEngineFailure()): this module has no request context
 * (requestId/tenantId) of its own to attach, and choosing audit event/metric
 * names now, before the wiring session decides how this plugs into
 * ../index.js's evidence and observability model, would likely need rework.
 * getStatus()'s return value remains this module's per-request observability
 * surface.
 *
 * is the one exception, and deliberately scoped: init()
 * emits a SINGLE boot-time event (EMBEDDING_CLASSIFIER_CONFIG_EFFECTIVE)
 * carrying the complete effective Five-gate threshold/flag configuration —
 * config.js's own PINNED_DEFAULTS alongside the effective (env-overridden)
 * values — plus a WARN (EMBEDDING_CLASSIFIER_CONFIG_DEVIATION) when running
 * in production with any value overridden away from its pinned default. This
 * needs no request context (it is a pure function of config.js's module-load-
 * time state) and does not change the "no per-request emission" decision
 * above at all — see config.js's PINNED_DEFAULTS/getDeviations() header
 * comments for the full rationale.
 */

const fs = require('fs');
const path = require('path');

const { loadModel, embed, embedBatch, cosineSim, MODEL } = require('./embeddingBackend');
const { loadAnchorTexts } = require('./anchorSet');
const {
  SIMILARITY_THRESHOLD, FAMILY_SIMILARITY_THRESHOLDS, thresholdForFamily,
  HEAD_SCORE_THRESHOLD, V9_SCORE_THRESHOLD, V5_SCORE_THRESHOLD,
  EMBEDDING_ENABLED,
  FT2_ENABLED, FT2_BAND_B_LO, FT2_FAMILY_THRESHOLDS,
  FT3_ENABLED, FT3_BAND_B_LO, FT3_FAMILY_THRESHOLDS,
  NORMALIZE_ENABLED,
  INTENT_GATE_ENABLED,
  TAIL_WINDOW_ENABLED,
  PINNED_DEFAULTS, getDeviations,
} = require('./config');
// negation/protective/reporting post-score intent gate. See that
// module's header for the mechanism and classify()/_classifyText() below for
// where it runs (the LAST step, on whichever text produced the final result).
const intentGate = require('./intentGate');
// input normalization for the embedding path. See classify() below
// for the ordering and that module's header for why the pipeline this repo
// already owned was reaching the wrong layer.
const { candidatesFor } = require('./inputNormalization');
const { emit } = require('../../../../services/logger');
const { rawFeatures, EXTRA: V9_EXTRA } = require('./v9Features');
const { verifyModelIntegrityOnce } = require('./modelIntegrity');
const ft2Gate = require('./ft2Gate');
const ft3Gate = require('./ft3Gate');
const { DECISION, ENGINE_STATUS } = require('../reasons');

// · B-3 — the frozen ensemble head, loaded from a PRODUCTION path.
// It previously lived in scripts/spikes/, whose own artifact note reads "NOT
// WIRED"; shipping decision-path behaviour out of an explicitly unapproved
// directory is not acceptable, so B-3 moved the byte-identical file here
// (sha256 unchanged: 672534dd…, pinned in __tests__/thresholdPinning.test.js).
const HEAD_MODEL_PATH = path.join(__dirname, 'headModel.json');

// · B-2 (a') — the V9 gate's frozen weights, same production-path
// discipline as headModel.json (sha256 fed484f6…, pinned in
// __tests__/thresholdPinning.test.js).
const V9_MODEL_PATH = path.join(__dirname, 'v9Model.json');

// · B-2 (b) union — the V5 gate's frozen weights. Same production-path
// discipline (sha256 20f9cc4c…, pinned in __tests__/thresholdPinning.test.js).
const V5_MODEL_PATH = path.join(__dirname, 'v5Model.json');

const BOOT_STATUS = Object.freeze({
  UNINITIALIZED: 'UNINITIALIZED',
  LOADING:       'LOADING',
  READY:         'READY',
  FAILED:        'FAILED',
  DISABLED:      'DISABLED',
});

let _boot = { status: BOOT_STATUS.UNINITIALIZED, anchors: null, head: null, v9: null, v5: null, ft2: null, ft3: null, error: null };

/**
 * Loads and validates the frozen ensemble head. Throws on any structural
 * problem — init()'s try/catch turns that into a FAILED boot, which the gate
 * renders as DENY. That is deliberate and matches D5/AI-2: a half-loaded
 * second gate must never degrade silently into "anchors only", because the
 * system would then quietly ship less detection than its own record claims
 * while every status surface still read READY.
 */
function _loadHeadModel() {
  const raw = JSON.parse(fs.readFileSync(HEAD_MODEL_PATH, 'utf8'));
  if (!Number.isFinite(raw.bias)) throw new Error('head model: bias is not finite');
  if (!Number.isInteger(raw.dim) || raw.dim <= 0) throw new Error('head model: dim is not a positive integer');
  if (!Array.isArray(raw.weights) || raw.weights.length !== raw.dim) {
    throw new Error(`head model: expected ${raw.dim} weights, got ${Array.isArray(raw.weights) ? raw.weights.length : typeof raw.weights}`);
  }
  if (!raw.weights.every(Number.isFinite)) throw new Error('head model: weights contain a non-finite value');
  return Object.freeze({ bias: raw.bias, dim: raw.dim, weights: Object.freeze(raw.weights) });
}

/**
 * · B-3 — the head's score for an already-computed embedding.
 *
 * Deliberately takes the VECTOR, not the text: the anchor stage has already
 * paid for embed() by the time this runs, so the head's entire marginal cost
 * is one 384-dim dot product plus one exp(). That is what keeps the integrated
 * path inside D6; scoring the head anywhere that forced a second embed() call
 * (e.g. up in embeddingGate.js) would roughly double gate latency for no gain.
 */
function _headScore(vector) {
  const { bias, dim, weights } = _boot.head;
  let z = bias;
  for (let d = 0; d < dim; d++) z += weights[d] * vector[d];
  return 1 / (1 + Math.exp(-z));
}

/**
 * Loads and validates V9's frozen weights. Same fail-closed contract as
 * _loadHeadModel(): a structurally broken third gate must take the boot down
 * rather than silently degrade to "anchors + head only", which would ship
 * less detection than the record claims while every status surface still read
 * READY.
 */
function _loadV9Model() {
  const raw = JSON.parse(fs.readFileSync(V9_MODEL_PATH, 'utf8'));
  if (!Number.isFinite(raw.bias)) throw new Error('v9 model: bias is not finite');
  if (raw.embDim !== 384) throw new Error(`v9 model: embDim ${raw.embDim} != 384`);
  if (raw.extra !== V9_EXTRA) throw new Error(`v9 model: extra ${raw.extra} != ${V9_EXTRA} (feature contract drift)`);
  if (!Array.isArray(raw.weights) || raw.weights.length !== raw.embDim + raw.extra) {
    throw new Error(`v9 model: expected ${raw.embDim + raw.extra} weights, got ${Array.isArray(raw.weights) ? raw.weights.length : typeof raw.weights}`);
  }
  if (!raw.weights.every(Number.isFinite)) throw new Error('v9 model: weights contain a non-finite value');
  for (const k of ['featureMean', 'featureSd']) {
    if (!Array.isArray(raw[k]) || raw[k].length !== raw.extra) throw new Error(`v9 model: ${k} must have ${raw.extra} entries`);
    if (!raw[k].every(Number.isFinite)) throw new Error(`v9 model: ${k} contains a non-finite value`);
  }
  if (raw.featureSd.some((s) => s === 0)) throw new Error('v9 model: featureSd contains a zero (would divide by zero)');
  if (!Number.isFinite(raw.featureScale)) throw new Error('v9 model: featureScale is not finite');
  return Object.freeze({
    bias: raw.bias,
    embDim: raw.embDim,
    extra: raw.extra,
    weights: Object.freeze(raw.weights),
    featureMean: Object.freeze(raw.featureMean),
    featureSd: Object.freeze(raw.featureSd),
    featureScale: raw.featureScale,
  });
}

/**
 * Loads and validates V5's frozen weights. Same fail-closed contract as the
 * other two heads — a structurally broken fourth gate takes the boot down
 * rather than silently degrading to three gates.
 */
function _loadV5Model() {
  const raw = JSON.parse(fs.readFileSync(V5_MODEL_PATH, 'utf8'));
  if (!Number.isFinite(raw.bias)) throw new Error('v5 model: bias is not finite');
  if (raw.embDim !== 384) throw new Error(`v5 model: embDim ${raw.embDim} != 384`);
  // V5 is deliberately feature-free: the (a') feature analysis measured 13 of
  // the 21 auxiliary signals CONSTANT on the eval split, and V5's recipe never
  // used them. A non-zero `extra` here would mean the wrong artifact was shipped.
  if (raw.extra !== 0) throw new Error(`v5 model: extra ${raw.extra} != 0 (V5 takes no auxiliary features)`);
  if (!Array.isArray(raw.weights) || raw.weights.length !== raw.embDim) {
    throw new Error(`v5 model: expected ${raw.embDim} weights, got ${Array.isArray(raw.weights) ? raw.weights.length : typeof raw.weights}`);
  }
  if (!raw.weights.every(Number.isFinite)) throw new Error('v5 model: weights contain a non-finite value');
  return Object.freeze({ bias: raw.bias, embDim: raw.embDim, weights: Object.freeze(raw.weights) });
}

/**
 * · B-2 (b) union — V5's score for an already-computed embedding.
 *
 * Takes only the VECTOR: V5 uses no auxiliary features, so its entire marginal
 * cost is one 384-dim dot product plus one exp(). Measured at 0.0005ms per
 * window against 0.0959ms for the three gates it joins — roughly 190x cheaper
 * than the rest of the gate stack combined.
 */
function _v5Score(vector) {
  const { bias, embDim, weights } = _boot.v5;
  let z = bias;
  for (let d = 0; d < embDim; d++) z += weights[d] * vector[d];
  return 1 / (1 + Math.exp(-z));
}

/**
 * · B-2 (a') — V9's score for an already-computed embedding plus the
 * window's own text.
 *
 * Takes the VECTOR as well as the text for the same reason _headScore() does:
 * 405-dim dot product plus the 21 auxiliary signals — no second model pass.
 * The features are standardised with the TRAIN-time statistics carried in the
 * model file, never recomputed from live traffic, so the transform is frozen
 * exactly as it was when the reported figures were measured.
 */
function _v9Score(vector, text) {
  const { bias, embDim, extra, weights, featureMean, featureSd, featureScale } = _boot.v9;
  let z = bias;
  for (let d = 0; d < embDim; d++) z += weights[d] * vector[d];
  const f = rawFeatures(text);
  for (let d = 0; d < extra; d++) {
    z += weights[embDim + d] * (((f[d] - featureMean[d]) / featureSd[d]) * featureScale);
  }
  return 1 / (1 + Math.exp(-z));
}

/**
 * Loads the model and computes anchor-set embeddings once. Must be awaited
 * at boot before classify() is used for real decisions; classify() fails
 * closed on its own if called beforehand, but that is a safety net, not the
 * intended call pattern.
 *
 * @returns {Promise<ReturnType<typeof getStatus>>}
 */
async function init() {
  if (!EMBEDDING_ENABLED) {
    // Deliberately off (QODIQA_SEM_EMBEDDING_ENABLED=false): nothing is verified or loaded, and embeddingGate never calls classify().
    _boot = { status: BOOT_STATUS.DISABLED, anchors: null, head: null, v9: null, v5: null, ft2: null, ft3: null, error: null };
    return getStatus();
  }
  _boot = { status: BOOT_STATUS.LOADING, anchors: null, head: null, v9: null, v5: null, ft2: null, ft3: null, error: null };
  try {
    // · BEFORE loadModel(), deliberately. A drifted or
    // tampered artifact must never reach the ONNX runtime at all, so the
    // check runs ahead of the load rather than alongside it. Fail-closed
    // exactly like B-3's corrupt-model path: this throw lands in the catch
    // below, boot goes FAILED, and ../embeddingGate.js renders that as DENY.
    //
    // Scope: provenance at boot, memoised per process. NOT a runtime
    // anti-tamper guard — see modelIntegrity.js.
    const integrity = verifyModelIntegrityOnce();
    if (!integrity.ok) {
      throw new Error(`embedding model integrity: ${integrity.failures.join('; ')}`);
    }

    await loadModel();

    const anchorTexts = loadAnchorTexts();
    const anchors = [];
    for (const item of anchorTexts) {
      anchors.push({ id: item.id, family: item.family, vector: await embed(item.text) });
    }
    if (anchors.length === 0) {
      throw new Error('anchor set resolved to zero items — corpus filter mismatch?');
    }

    // Read from disk once, at boot — never per request. Combined with the
    // model cache this keeps the whole classifier zero-network (SEM-F/D3):
    // the head is a local JSON file plus arithmetic, with no fetch path.
    const head = _loadHeadModel();
    if (head.dim !== anchors[0].vector.length) {
      throw new Error(`head model dim ${head.dim} != embedding dim ${anchors[0].vector.length}`);
    }

    const v9 = _loadV9Model();
    if (v9.embDim !== anchors[0].vector.length) {
      throw new Error(`v9 model embDim ${v9.embDim} != embedding dim ${anchors[0].vector.length}`);
    }

    const v5 = _loadV5Model();
    if (v5.embDim !== anchors[0].vector.length) {
      throw new Error(`v5 model embDim ${v5.embDim} != embedding dim ${anchors[0].vector.length}`);
    }

    // ── · fine-tune v1 — FIFTH GATE, FLAG-GATED ────────────────────
    // Loaded ONLY when QODIQA_SEM_FT2_ENABLED is true. With the flag off this
    // block is skipped entirely: no integrity check, no 90 MB read, no ONNX
    // session, no 65 extra forward passes, and `ft2` stays null so
    // _maybeFifthGate() is a no-op. That is what makes "flag off is
    // byte-identical to the four-gate path" a structural property rather than
    // a claim needing trust.
    let ft2 = null;
    if (FT2_ENABLED) {
      await ft2Gate.load();
      const ft2Anchors = await ft2Gate.buildAnchors(anchorTexts);
      if (ft2Anchors.size === 0) throw new Error('ft2: anchor set resolved to zero families');
      ft2 = { anchors: ft2Anchors };
    }

    // ── · fine-tune v2 — SIXTH GATE, FLAG-GATED ────────────────────
    // Identical structure and identical guarantee to the FT-2 block above, and
    // for the same reason: with QODIQA_SEM_FT3_ENABLED off (the shipped
    // default) nothing here runs — no integrity check, no 90 MB read, no ONNX
    // session, no 65 extra forward passes — and `ft3` stays null so
    // _maybeSixthGate() is a no-op. "Flag off is byte-identical to the
    // five-gate path" is therefore structural, not a claim needing trust.
    let ft3 = null;
    if (FT3_ENABLED) {
      await ft3Gate.load();
      const ft3Anchors = await ft3Gate.buildAnchors(anchorTexts);
      if (ft3Anchors.size === 0) throw new Error('ft3: anchor set resolved to zero families');
      ft3 = { anchors: ft3Anchors };
    }

    _boot = { status: BOOT_STATUS.READY, anchors, head, v9, v5, ft2, ft3, error: null };
  } catch (err) {
    _boot = { status: BOOT_STATUS.FAILED, anchors: null, head: null, v9: null, v5: null, ft2: null, ft3: null, error: (err && err.message) || 'unknown embedding classifier boot error' };
  }
  _emitEffectiveConfig();
  return getStatus();
}

/**
 * single auditable boot event for the complete effective Five-gate
 * semantic configuration (every threshold + both FT flags), plus a
 * production-only WARN when any of them deviates from its pinned default.
 *
 * Called exactly once per init() call, unconditionally (READY or FAILED):
 * every value here comes from config.js's module-load-time state, which is
 * fully resolved (env overrides already applied) regardless of whether model
 * loading itself succeeded — so the configuration that WAS in effect for
 * this boot attempt is always worth recording, including when boot failed
 * (an operator diagnosing a FAILED boot may need exactly this to see whether
 * an env override caused it).
 *
 * Narrowly scoped by design (see this file's header comment and config.js's
 * PINNED_DEFAULTS/getDeviations()): only Five-gate thresholds and the two FT
 * flags are read. Never touches process.env directly, never logs secrets —
 * there are none in this configuration surface (see config.js: every value
 * here is a float threshold or a boolean flag).
 */
function _emitEffectiveConfig() {
  const thresholds = {
    similarityThreshold:        { default: PINNED_DEFAULTS.similarityThreshold, effective: SIMILARITY_THRESHOLD },
    familySimilarityThresholds: { default: PINNED_DEFAULTS.familySimilarityThresholds, effective: FAMILY_SIMILARITY_THRESHOLDS },
    headScoreThreshold:         { default: PINNED_DEFAULTS.headScoreThreshold, effective: HEAD_SCORE_THRESHOLD },
    v9ScoreThreshold:           { default: PINNED_DEFAULTS.v9ScoreThreshold, effective: V9_SCORE_THRESHOLD },
    v5ScoreThreshold:           { default: PINNED_DEFAULTS.v5ScoreThreshold, effective: V5_SCORE_THRESHOLD },
    ft2BandBLo:                 { default: PINNED_DEFAULTS.ft2BandBLo, effective: FT2_BAND_B_LO },
    ft2FamilyThresholds:        { default: PINNED_DEFAULTS.ft2FamilyThresholds, effective: FT2_FAMILY_THRESHOLDS },
    ft3BandBLo:                 { default: PINNED_DEFAULTS.ft3BandBLo, effective: FT3_BAND_B_LO },
    ft3FamilyThresholds:        { default: PINNED_DEFAULTS.ft3FamilyThresholds, effective: FT3_FAMILY_THRESHOLDS },
  };
  const flags = {
    ft2Enabled: { default: PINNED_DEFAULTS.ft2Enabled, effective: FT2_ENABLED },
    ft3Enabled: { default: PINNED_DEFAULTS.ft3Enabled, effective: FT3_ENABLED },
    // input normalization changes which TEXT the gates score, so it
    // belongs in the effective-configuration record for exactly the reason the
    // thresholds do: a figure quoted without it is not reproducible.
    normalizeEnabled: { default: PINNED_DEFAULTS.normalizeEnabled, effective: NORMALIZE_ENABLED },
    // the intent gate changes which DENYs survive to the caller, so
    // it belongs in the effective-configuration record for the same reason.
    intentGateEnabled: { default: PINNED_DEFAULTS.intentGateEnabled, effective: INTENT_GATE_ENABLED },
  };
  const deviations = getDeviations();

  emit('INFO', 'EMBEDDING_CLASSIFIER_CONFIG_EFFECTIVE', {
    schemaVersion: 1,
    bootStatus:    _boot.status,
    thresholds,
    flags,
    deviatesFromPinnedDefaults: deviations.length > 0,
  });

  // Action 2 — production-profile deviation warning. Informational only: it
  // never rejects, clamps, or resets a value, and never fires outside
  // production (matching the repo's existing NODE_ENV==='production' profile
  // check — see e.g. src/infra/secrets/secretValidation.js's
  // _checkProductionKmsProvider() for the same pattern applied to the KMS
  // deviations is empty and this block is skipped entirely.
  if (process.env.NODE_ENV === 'production' && deviations.length > 0) {
    emit('WARN', 'EMBEDDING_CLASSIFIER_CONFIG_DEVIATION', {
      message: 'Effective Five-gate semantic configuration differs from pinned defaults in ' +
               'production. This is informational — overrides remain in effect and no value ' +
               'was changed, clamped, or rejected by this warning.',
      deviationCount: deviations.length,
      deviations,
    });
  }
}

/**
 * @returns {{status: string, anchorCount: number, model: string, threshold: number, headLoaded: boolean, headThreshold: number, error: string|null}}
 */
function getStatus() {
  return Object.freeze({
    status:        _boot.status,
    anchorCount:   _boot.anchors ? _boot.anchors.length : 0,
    model:         MODEL,
    threshold:     SIMILARITY_THRESHOLD,
    // B-3: the second gate is part of the shipped decision path, so its
    // presence and bar belong on the module's observability surface. A READY
    // status with headLoaded false is impossible by construction (init()
    // fails closed), but reporting it makes that guarantee checkable.
    headLoaded:    _boot.head !== null,
    headThreshold: HEAD_SCORE_THRESHOLD,
    // B-2 (a'): the third gate, same rationale as headLoaded above.
    v9Loaded:      _boot.v9 !== null,
    v9Threshold:   V9_SCORE_THRESHOLD,
    // B-2 (b): the fourth gate, same rationale.
    v5Loaded:      _boot.v5 !== null,
    v5Threshold:   V5_SCORE_THRESHOLD,
    // fine-tune v1: the fifth gate. `ft2Enabled` is the FLAG; `ft2Loaded` is
    // whether the model is actually resident. Both are reported because
    // enabled-but-not-loaded is the state a failed boot would show, and a
    // dashboard that showed only one of them could not tell the difference.
    ft2Enabled:    FT2_ENABLED,
    ft2Loaded:     _boot.ft2 !== null,
    ft2BandBLo:    FT2_BAND_B_LO,
    // fine-tune v2 (FT-3): the fine-tuned gate that is ON by default since the 2026-08-19 swap (FT-2, above, is the one shipped
    // disabled). Same enabled/loaded pair and same reason as FT-2's above.
    ft3Enabled:    FT3_ENABLED,
    ft3Loaded:     _boot.ft3 !== null,
    ft3BandBLo:    FT3_BAND_B_LO,
    // input normalization. A flag only: unlike the FT gates there is
    // no artifact to load, so there is no enabled-but-not-loaded state to
    // distinguish and no second field to report.
    normalizeEnabled: NORMALIZE_ENABLED,
    // the post-score intent gate. A flag only, like normalizeEnabled:
    // no artifact to load, so no enabled-but-not-loaded state to distinguish.
    intentGateEnabled: INTENT_GATE_ENABLED,
    error:         _boot.error,
  });
}

function _denyClassifierFailure(failureReason) {
  return Object.freeze({
    decision:       DECISION.DENY,
    score:          null,
    threshold:      SIMILARITY_THRESHOLD,
    matchedAnchorId: null,
    headScore:      null,
    headFired:      false,
    v9Score:        null,
    v9Fired:        false,
    v5Score:        null,
    v5Fired:        false,
    matchedBy:      null,
    engineStatus:   ENGINE_STATUS.UNAVAILABLE,
    failureReason,
  });
}

// SEM-C session 3: Xenova/all-MiniLM-L6-v2 silently truncates to its
// 512-token max_length — empirically confirmed (a 5,400-char prefix
// followed by two completely different tails produced byte-identical
// embeddings; cosine sim 1.0). Scoring a single classify() call against
// arbitrarily long text would silently ignore anything past that limit —
// e.g. an attack payload appended after enough benign padding. 400 chars is
// a conservative per-window budget: empirically, realistic English tokenizes
// at ~5-6 chars/token (well under 512 tokens for 400 chars), and even a
// pathological worst case (~1 token/char for OOV/rare content) stays under
// 512. WINDOW_OVERLAP_CHARS mirrors outputSemanticWindow.js's identical
// boundary-pattern rationale — a match straddling a window edge is still
// caught in at least one window.
//
// (S2c): the stride below covers every position but its own final
// window can still be SHORTER than MAX_CHARS_PER_WINDOW when text.length
// isn't an exact stride multiple — see TAIL_WINDOW_ENABLED (config.js) and
// _appendTailWindow() below for the flag-gated, additive fix.
const MAX_CHARS_PER_WINDOW = 400;
const WINDOW_OVERLAP_CHARS = 50;

/**
 * (S2c) — flag-gated tail-window guarantee. See TAIL_WINDOW_ENABLED's
 * header in config.js for the full rationale and safety argument.
 *
 * The fixed stride above already covers every position of `text` (that is
 * what WINDOW_OVERLAP_CHARS is for), but its own FINAL window can land short
 * of a full MAX_CHARS_PER_WINDOW-character window whenever `text.length`
 * isn't an exact multiple of the stride — e.g. an 8,000-char input's last
 * natural window is only 300 characters, not the full 400-character budget
 * every other window gets, diluting the tail's own embedding differently than
 * an undiluted full-budget window would. This appends one additional window
 * — exactly the last MAX_CHARS_PER_WINDOW characters of `text` — UNLESS it is
 * already identical to the stride's own last window (the common case when
 * `text.length` happens to land on a stride boundary, e.g. exactly 1,800
 * nothing beyond one additional classify() window pass in the case where it
 * would otherwise be missing, and never scores the same text twice.
 *
 * Purely additive over `windows`: never removes or reorders an existing
 * window, so every property `_splitIntoWindows()`'s caller already relies on
 * (worst-of-all-windows selection, fail-closed on any window's failure) is
 * unaffected — this only ever grows the candidate set the worst-case
 * selection runs over.
 */
function _appendTailWindow(text, windows) {
  if (!TAIL_WINDOW_ENABLED || text.length <= MAX_CHARS_PER_WINDOW) return windows;
  const tailWindow = text.slice(text.length - MAX_CHARS_PER_WINDOW);
  if (windows.length > 0 && windows[windows.length - 1] === tailWindow) return windows;
  windows.push(tailWindow);
  return windows;
}

function _splitIntoWindows(text) {
  const windows = [];
  const step = MAX_CHARS_PER_WINDOW - WINDOW_OVERLAP_CHARS;
  for (let start = 0; start < text.length; start += step) {
    windows.push(text.slice(start, start + MAX_CHARS_PER_WINDOW));
    if (start + MAX_CHARS_PER_WINDOW >= text.length) break;
  }
  return _appendTailWindow(text, windows);
}

/**
 * Scores a single window of text (<=MAX_CHARS_PER_WINDOW, by contract of
 * the only caller, classify() below) against the boot-computed anchor set
 * and returns a DENY/ALLOW decision by max cosine similarity vs. threshold.
 */
// (step 3): `preVector` is the window's embedding when the caller already embedded every window of the text in
// one batched call; scoring below is unchanged and reads only `vector`.
async function _classifyWindow(text, preVector) {
  if (_boot.status !== BOOT_STATUS.READY) {
    return _denyClassifierFailure('EMBEDDING_CLASSIFIER_NOT_READY');
  }

  let vector = preVector;
  if (vector === undefined) {
    try {
      vector = await embed(text);
    } catch {
      return _denyClassifierFailure('EMBEDDING_INFERENCE_FAILED');
    }
  }

  try {
    // threshold, not one global value. `maxSim` and the reported `score` keep
    // their previous meaning — the highest similarity to any anchor — so
    // every existing consumer of `score` (evidence, calibration tooling, the
    // measurement harness) is unaffected. What changes is only which
    // comparison decides DENY.
    //
    // DENY if ANY family's own best similarity clears that family's own
    // threshold. Because thresholdForFamily() is capped at the global value,
    // this can only ever add detections relative to the previous behaviour,
    // never remove one.
    let maxSim = -Infinity;
    // The deciding anchor among those that cleared their own family's bar —
    // the highest-scoring such anchor, so the reported match is the strongest
    // evidence rather than whichever happened to be iterated first.
    let denyAnchorId = null;
    let denyFamily = null;
    let denySim = -Infinity;
    for (const anchor of _boot.anchors) {
      const sim = cosineSim(vector, anchor.vector);
      if (sim > maxSim) maxSim = sim;
      if (sim >= thresholdForFamily(anchor.family) && sim > denySim) {
        denyAnchorId = anchor.id;
        denyFamily = anchor.family;
        denySim = sim;
      }
    }
    if (!Number.isFinite(maxSim)) {
      return _denyClassifierFailure('SCORING_PRODUCED_NON_FINITE_RESULT');
    }

    // ── · B-3 — SECOND GATE ─────────────────────────────────────────
    // The frozen ensemble head, scored on the SAME `vector` the anchor loop
    // just consumed. Reproduces b2-external-validation.js's rule exactly,
    // including the STRICT `>` (the anchor comparison is `>=`); that asymmetry
    // is inherited from the measurement and is not a typo to "fix".
    const headScore = _headScore(vector);
    if (!Number.isFinite(headScore)) {
      return _denyClassifierFailure('HEAD_SCORING_PRODUCED_NON_FINITE_RESULT');
    }
    const headFired = headScore > HEAD_SCORE_THRESHOLD;
    const anchorFired = denyAnchorId !== null;

    // ── · B-2 (a') — THIRD GATE ─────────────────────────────────────
    // V9, scored on the SAME `vector` plus this window's own text. Strict `>`
    // again, inherited from the measurement rather than chosen.
    const v9Score = _v9Score(vector, text);
    if (!Number.isFinite(v9Score)) {
      return _denyClassifierFailure('V9_SCORING_PRODUCED_NON_FINITE_RESULT');
    }
    const v9Fired = v9Score > V9_SCORE_THRESHOLD;

    // ── · B-2 (b) union — FOURTH GATE ───────────────────────────────
    // V5, on the same `vector`. No features, no text — one dot product.
    const v5Score = _v5Score(vector);
    if (!Number.isFinite(v5Score)) {
      return _denyClassifierFailure('V5_SCORING_PRODUCED_NON_FINITE_RESULT');
    }
    const v5Fired = v5Score > V5_SCORE_THRESHOLD;

    // The ensemble rule: OR, now over four terms. Still monotone, so it can
    //
    // so the union banks 12 where either alone banks 9. That disjointness is
    // the whole reason the fourth gate exists.
    const decision = (anchorFired || headFired || v9Fired || v5Fired) ? DECISION.DENY : DECISION.ALLOW;

    return Object.freeze({
      decision,
      // UNCHANGED MEANING: the highest similarity to any anchor.'s score
      // this field, so B-3 does not redefine it — the head reports through the
      // new fields below instead, and no existing consumer shifts meaning.
      score:           Number(maxSim.toFixed(4)),
      // The threshold actually applied to the deciding anchor's family, so the
      // reported value always explains the reported decision. Falls back to the
      // global value where no family was decisive (ALLOW, or a head-only DENY).
      threshold:       anchorFired ? thresholdForFamily(denyFamily) : SIMILARITY_THRESHOLD,
      matchedAnchorId: anchorFired ? denyAnchorId : null,
      headScore:       Number(headScore.toFixed(6)),
      headFired,
      v9Score:         Number(v9Score.toFixed(6)),
      v9Fired,
      v5Score:         Number(v5Score.toFixed(6)),
      v5Fired,
      // Which gate(s) produced this decision — the audit trail's answer to
      // "why was this denied", and the field that makes each gate's live
      // contribution measurable in production rather than only offline.
      //
      // Built from a fixed order and joined with '+', so B-3's existing values
      // ('anchor', 'head', 'anchor+head') are reproduced byte-identically and
      matchedBy:       decision === DECISION.DENY
        ? [anchorFired && 'anchor', headFired && 'head', v9Fired && 'v9', v5Fired && 'v5'].filter(Boolean).join('+')
        : null,
      engineStatus:    ENGINE_STATUS.READY,
      failureReason:   null,
    });
  } catch {
    return _denyClassifierFailure('SCORING_FAILED');
  }
}

/**
 * Window-selection ordering: DENY strictly outranks ALLOW, and only among
 * windows of the SAME decision does the anchor score break the tie.
 *
 * · B-3 fixed a live-path defect here. The previous rule compared
 * `result.score` alone — the max ANCHOR cosine. Once the head can deny on its
 * own, a window denied by the head at a low anchor cosine would lose that
 * comparison to a higher-cosine window the system ALLOWED, and `classify()`
 * would return ALLOW for text one of whose windows was denied. That silently
 * discards a real detection, and it defeats the documented "one matching
 * window is enough to DENY the whole text" contract. Decision first, score
 * second is the only ordering consistent with that contract.
 */
function _isWorseThan(candidate, incumbent) {
  const cDeny = candidate.decision === DECISION.DENY;
  const iDeny = incumbent.decision === DECISION.DENY;
  if (cDeny !== iDeny) return cDeny;
  return candidate.score > incumbent.score;
}

/**
 * Scores `text` against the boot-computed anchor set. Text at or under
 * MAX_CHARS_PER_WINDOW is a single _classifyWindow() call, byte-identical
 * to this module's pre-session-3 behavior. Longer text is split into
 * overlapping windows (see MAX_CHARS_PER_WINDOW's comment above for why —
 * the backend silently truncates otherwise) and scored as the worst
 * (highest-similarity, or first failure) result across all windows — one
 * matching window is enough to DENY the whole text, and one failing window
 * is enough to fail the whole text closed; a failure is never silently
 * skipped in favor of a later window's success.
 *
 * @param {string} text
 */
/**
 * THE FIFTH GATE — FT-2, flag-gated, band-gated, best-window-only.
 *
 * Runs AFTER the window loop has already chosen its window, on that ONE window,
 * for three reasons that are all load-bearing:
 *
 *   1. FT-2 is a different encoder, so it needs its own forward pass. Running
 *      it per window would multiply the entire integration cost by the window
 *      count — measured at 760ms p95 on long prompts under load.
 *      among same-decision windows (see _isWorseThan), which is exactly the
 *      "best window" the reduction round approved. It costs nothing extra to
 *      reuse it, whereas the offline harness had to re-score every window from
 *      outside the module to find it — a harness artifact that must not reach
 *      production, and does not.
 *      window already computed. No second anchor pass.
 *
 * MONOTONE OR PRESERVED: this can only turn ALLOW into DENY. It never inspects
 * a window the loop rejected, never lowers a DENY, and returns the incumbent
 * result object untouched in every path but a fresh denial.
 *
 * FAIL-CLOSED: an inference throw becomes a DENY through the classifier-failure
 * shape, exactly as an embed() failure does for the first four gates.
 */
async function _maybeFifthGate(result, windowText) {
  if (!FT2_ENABLED || _boot.ft2 === null) return result;
  if (!result || result.engineStatus !== ENGINE_STATUS.READY) return result;
  // Already denied by a cheap gate — the OR is monotone, so a second opinion
  // cannot change the outcome and is pure cost.
  if (result.decision === DECISION.DENY) return result;
  // Grey band: below B_lo the item is confidently benign and FT-2 is skipped.
  if (!(typeof result.score === 'number' && result.score >= FT2_BAND_B_LO)) return result;

  let ft2;
  try {
    const vector = await ft2Gate.embed(windowText);
    ft2 = ft2Gate.score(vector, _boot.ft2.anchors);
  } catch {
    return _denyClassifierFailure('FT2_SCORING_FAILED');
  }
  if (!Number.isFinite(ft2.score)) return _denyClassifierFailure('FT2_SCORING_PRODUCED_NON_FINITE_RESULT');
  if (!ft2.fired) {
    // Not a denial, but the margin is worth carrying: near-band ALLOWs are the
    // population an enable decision needs to watch. `ft2Consulted` is what lets
    // embeddingGate.js compute the invocation rate without re-deriving the band
    // — and it is absent, not false, on every path where the gate did not run,
    // so the flag-off output stays free of ft2 keys entirely.
    return Object.freeze({
      ...result, ft2Consulted: true, ft2Score: Number(ft2.score.toFixed(6)), ft2Fired: false, ft2Family: ft2.family,
    });
  }
  return Object.freeze({
    ...result,
    decision:  DECISION.DENY,
    ft2Consulted: true,
    ft2Score:  Number(ft2.score.toFixed(6)),
    ft2Fired:  true,
    ft2Family: ft2.family,
    // Fixed-order join, same convention as the four-gate matchedBy, so existing
    // values are reproduced byte-identically and only '+ft2' is ever appended.
    matchedBy: result.matchedBy ? `${result.matchedBy}+ft2` : 'ft2',
  });
}

/**
 * THE SIXTH GATE — FT-3, flag-gated, band-gated, best-window-only.
 *
 * Structurally identical to _maybeFifthGate() above, and runs immediately after
 * it on the same chosen window. Every argument in that function's header
 * applies here unchanged: FT-3 is a third distinct encoder, so it needs its own
 * forward pass; the window is already the best-window the loop selected; and
 * the band reuses the anchor score that window already computed.
 *
 * ORDERING, and why it does not matter for correctness: FT-3 runs after FT-2,
 * but both are monotone ALLOW->DENY transforms reading the same immutable
 * window, so the composition commutes on the decision. It matters only for
 * COST — if FT-2 already denied, FT-3 short-circuits and never pays its forward
 * pass, which would be the cheaper ordering if FT-2 were enabled.
 *
 * MONOTONE OR PRESERVED and FAIL-CLOSED: identical contracts to the fifth gate.
 */
async function _maybeSixthGate(result, windowText) {
  if (!FT3_ENABLED || _boot.ft3 === null) return result;
  if (!result || result.engineStatus !== ENGINE_STATUS.READY) return result;
  if (result.decision === DECISION.DENY) return result;
  if (!(typeof result.score === 'number' && result.score >= FT3_BAND_B_LO)) return result;

  let ft3;
  try {
    const vector = await ft3Gate.embed(windowText);
    ft3 = ft3Gate.score(vector, _boot.ft3.anchors);
  } catch {
    return _denyClassifierFailure('FT3_SCORING_FAILED');
  }
  if (!Number.isFinite(ft3.score)) return _denyClassifierFailure('FT3_SCORING_PRODUCED_NON_FINITE_RESULT');
  if (!ft3.fired) {
    return Object.freeze({
      ...result, ft3Consulted: true, ft3Score: Number(ft3.score.toFixed(6)), ft3Fired: false, ft3Family: ft3.family,
    });
  }
  return Object.freeze({
    ...result,
    decision:  DECISION.DENY,
    ft3Consulted: true,
    ft3Score:  Number(ft3.score.toFixed(6)),
    ft3Fired:  true,
    ft3Family: ft3.family,
    matchedBy: result.matchedBy ? `${result.matchedBy}+ft3` : 'ft3',
  });
}

/**
 * applies the post-score intent gate to a fully-formed ensemble
 * result, on the exact text that produced it. Called from both branches of
 * _classifyText() below (single-window and multi-window) so the gate sees
 * whichever text the ensemble actually decided on — the raw text, or the
 * worst-scoring window for long text. A no-op when the result is not DENY
 * (see intentGate.maybeOverride()'s own guard) or when the flag is off.
 */
function _maybeIntentGate(result, text) {
  if (!INTENT_GATE_ENABLED) return result;
  return intentGate.maybeOverride(result, text);
}

async function _classifyText(text) {
  if (typeof text !== 'string' || text.length <= MAX_CHARS_PER_WINDOW) {
    return _maybeIntentGate(await _maybeSixthGate(await _maybeFifthGate(await _classifyWindow(text), text), text), text);
  }

  let worst = null;
  let worstWindow = null;
  // (step 3): embed EVERY window of the text in ONE batched call (one worker task), then score the windows in
  // their original order with the unchanged selection below. An embedding failure fails the whole text closed,
  // exactly as the first failing window did before (a failure was never skipped for a later window's success).
  const windows = _splitIntoWindows(text);
  if (_boot.status !== BOOT_STATUS.READY) return _denyClassifierFailure('EMBEDDING_CLASSIFIER_NOT_READY');
  let vectors;
  try {
    vectors = await embedBatch(windows);
  } catch {
    return _denyClassifierFailure('EMBEDDING_INFERENCE_FAILED');
  }
  for (let i = 0; i < windows.length; i++) {
    const window = windows[i];
    // eslint-disable-next-line no-await-in-loop -- sequential by design: a
    // failing window must short-circuit immediately (fail closed), and
    // finding the true worst-case match requires scoring every window that
    // didn't fail.
    const result = await _classifyWindow(window, vectors[i]);
    if (result.engineStatus !== 'READY') return result;
    if (!worst || _isWorseThan(result, worst)) { worst = result; worstWindow = window; }
  }
  return _maybeIntentGate(await _maybeSixthGate(await _maybeFifthGate(worst, worstWindow), worstWindow), worstWindow);
}

/**
 * INPUT NORMALIZATION, as a monotone OR over candidate texts.
 *
 * The raw text is scored FIRST and in full, through the identical path it took
 * before this stage existed. Only then are candidate normalizations
 * (./inputNormalization.js) scored, and only while the raw result is a healthy
 * ALLOW. Three properties are structural rather than measured:
 *
 *   MONOTONE     the raw DENY is returned untouched and no candidate is even
 *                computed, so this stage cannot remove a detection. The whole
 *                adversarial baseline is therefore preserved by construction —
 *                the same argument the four-gate OR already rests on.
 *
 *   FAIL-CLOSED  a non-READY raw result returns immediately, and a non-READY
 *                CANDIDATE result also returns immediately rather than being
 *                skipped in favour of a later candidate's success. A failure to
 *                inspect is never converted into an ALLOW, which is the D5/AI-2
 *                contract every other path in this module holds.
 *
 *   INERT        candidatesFor() emits nothing unless a transform actually
 *                fired, so ordinary text costs exactly one embedding pass and
 *                returns an object carrying NO normalization fields at all —
 *                absent, not false, the same convention ft2Consulted/
 *                ft3Consulted already use. Flag-off is likewise structural: no
 *                candidate is computed and no field is added.
 *
 * WHAT IS DELIBERATELY NOT DONE HERE. The candidate does not replace the raw
 * text for reporting: on an ALLOW the raw result is returned, so `score` and
 * score distribution stays comparable across this change. Only a candidate that
 * DENIES surfaces, and it carries `normalizedBy` naming the transform
 * responsible, so every new denial is attributable to a named cause in the
 * audit trail rather than appearing as an unexplained shift in detection.
 */
async function classify(text) {
  const raw = await _classifyText(text);
  if (!NORMALIZE_ENABLED) return raw;
  // Fail-closed and monotone short-circuits, in that order.
  if (!raw || raw.engineStatus !== ENGINE_STATUS.READY) return raw;
  if (raw.decision === DECISION.DENY) return raw;

  let candidates;
  try {
    candidates = candidatesFor(text);
  } catch {
    // Candidate construction is a pure function of a string, but a failure in
    // it must degrade to the earlier behaviour — the raw verdict already in
    // hand — rather than denying traffic or throwing into the gate.
    return raw;
  }
  if (candidates.length === 0) return raw;

  for (const candidate of candidates) {
    // eslint-disable-next-line no-await-in-loop -- sequential by design, for the
    // same two reasons the window loop above is: the ONNX backend's native
    // binding is not safe for concurrent use, and a failing candidate must
    // short-circuit immediately rather than racing a later success.
    const result = await _classifyText(candidate.text);
    if (result.engineStatus !== ENGINE_STATUS.READY) return result;
    if (result.decision === DECISION.DENY) {
      return Object.freeze({
        ...result,
        normalizedBy: candidate.id,
        normalizationCandidates: candidates.length,
      });
    }
  }

  return Object.freeze({
    ...raw,
    normalizedBy: null,
    normalizationCandidates: candidates.length,
  });
}

// Test-only: resets boot state so a test can simulate "not yet initialized"
// or force a fresh init() without process restart — mirrors
// classifierRegistry.js's _resetDiscoveryForTests() pattern.
function _resetForTests() {
  _boot = { status: BOOT_STATUS.UNINITIALIZED, anchors: null, head: null, v9: null, v5: null, ft2: null, ft3: null, error: null };
}

module.exports = { init, classify, getStatus, BOOT_STATUS, _resetForTests };
