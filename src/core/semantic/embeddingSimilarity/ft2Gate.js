'use strict';

/**
 * FT-2 — THE FIFTH GATE (fine-tune v1).
 *
 * A contrastively fine-tuned all-MiniLM-L6-v2, served as ONNX fp32, scored as
 * anchor similarity in ITS OWN embedding space against per-family thresholds
 * derived by the blind-corrected calibration protocol.
 *
 * SHIPPED DISABLED. `QODIQA_SEM_FT2_ENABLED` defaults to false and nothing in
 * this module is loaded, embedded or executed while it is off — see index.js's
 * init(), which skips the load entirely. With the flag off the decision path is
 * byte-identical to the four-gate path.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THIS IS A SECOND MODEL PASS AND THE OTHER THREE GATES ARE NOT.
 *
 * computed, so each costs a dot product. FT-2 is a DIFFERENT ENCODER — its
 * vector cannot be derived from the frozen model's — so it needs its own
 * forward pass. That pass is the entire integration cost, and it is why this
 * gate is band-gated and best-window-only rather than run on everything.
 *
 * WHY fp32 AND NOT fp16. Measured: fp16 has no native CPU kernels in
 * onnxruntime, so the runtime inserts casts per op and the encoder runs ~2x
 * SLOWER than fp32 (idle p95 37.16ms vs 16.71ms; loaded 146.12ms vs 78.71ms).
 * The calibration below was derived on fp16; serving fp32 against it was
 * verified at ZERO decision flips across 2,062 items (|margin delta| max
 * 5.10e-4). fp16's smaller file bought nothing but latency.
 *
 * WHY intraOpNumThreads=1. Also measured: the default session claims every
 * core, and under contention that is worse than taking one. fp32 loaded p95
 * 64.48ms at 1 thread against 78.71ms at the default. Verified bit-identical
 * on 200 probes before adoption — no score is approximated for speed.
 *
 * FAIL-CLOSED, mirroring every other gate here and ../index.js's
 * _denyEngineFailure(): any load or inference failure surfaces as a DENY
 * through index.js, never as a silent ALLOW and never as a throw.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { FT2_FAMILY_THRESHOLDS, FT2_SESSION_INTRA_OP_THREADS } = require('./config');

/**
 * Vendored served artifact. Same rationale as's embedding-model pin: a
 * calibrated threshold is meaningless without the exact bytes it was calibrated
 * against, and this repo already commits its frozen corpora on that logic.
 *
 * COST DISCLOSED: 90,376,758 bytes. That is roughly double the whole of the
 * rest of the repository's history, and it is the price of fp32. It is
 * recorded here rather than discovered by whoever next clones.
 */
const MODEL_PATH = path.join(__dirname, '..', '..', '..', '..', 'eval', 'finetune-v1', 'served', 'ft2_fp32.onnx');
const MODEL_SHA256 = '08a250b128adf80dc49141cc9417cf6d480d4184228ae2693d650d0ce1ed22d9';

/**
 * TOKENIZER. Deliberately NOT a second vendored copy — FT-2 is a fine-tune of
 * all-MiniLM-L6-v2 and fine-tuning does not touch the vocabulary, so it shares
 * the tokenizer already pinned by modelIntegrity.js. Token-ID equality was
 * verified against the checkpoint's own HuggingFace tokenizer before this gate
 * was written (three probe strings, exact id-sequence match). Sharing the
 * pinned tokenizer means the seal covers both models.
 */
const MAX_LEN = 256;
const EMB_DIM = 384;

let _session = null;
let _tokenizer = null;

function verifyIntegrity() {
  if (!fs.existsSync(MODEL_PATH)) {
    return { ok: false, reason: `ft2 model missing at ${path.relative(process.cwd(), MODEL_PATH)}` };
  }
  const actual = crypto.createHash('sha256').update(fs.readFileSync(MODEL_PATH)).digest('hex');
  if (actual !== MODEL_SHA256) {
    return { ok: false, reason: `ft2 model sha256 ${actual.slice(0, 16)}… != pinned ${MODEL_SHA256.slice(0, 16)}…` };
  }
  return { ok: true, bytes: fs.statSync(MODEL_PATH).size };
}

/**
 * Loads the ONNX session and the shared tokenizer. Called from init() ONLY when
 * the flag is on, so a disabled gate costs nothing at boot.
 */
async function load() {
  const integrity = verifyIntegrity();
  if (!integrity.ok) throw new Error(`ft2 gate integrity: ${integrity.reason}`);

  const ort = require('onnxruntime-node');
  _session = await ort.InferenceSession.create(MODEL_PATH, {
    intraOpNumThreads: FT2_SESSION_INTRA_OP_THREADS,
  });

  const { AutoTokenizer, env } = await import('@xenova/transformers');
  const { MODEL_DIR } = require('./modelIntegrity');
  env.localModelPath = MODEL_DIR;
  env.allowLocalModels = true;
  env.allowRemoteModels = false;
  _tokenizer = await AutoTokenizer.from_pretrained('Xenova/all-MiniLM-L6-v2');
  return { bytes: integrity.bytes };
}

/**
 * Mean-pools and L2-normalises one text into FT-2 space. Identical arithmetic
 * to the calibration harness — mean over unmasked positions, then normalise.
 */
async function embed(text) {
  const ort = require('onnxruntime-node');
  const enc = await _tokenizer(text, { truncation: true, max_length: MAX_LEN });
  const n = enc.input_ids.data.length;
  const dims = [1, n];
  const ids = BigInt64Array.from(Array.from(enc.input_ids.data, (x) => BigInt(x)));
  const mask = BigInt64Array.from(Array.from(enc.attention_mask.data, (x) => BigInt(x)));
  const out = await _session.run({
    input_ids: new ort.Tensor('int64', ids, dims),
    attention_mask: new ort.Tensor('int64', mask, dims),
    token_type_ids: new ort.Tensor('int64', new BigInt64Array(n), dims),
  });
  const h = out.last_hidden_state.data;
  const v = new Float64Array(EMB_DIM);
  let kept = 0;
  for (let t = 0; t < n; t++) {
    if (Number(mask[t]) === 0) continue;
    kept += 1;
    for (let d = 0; d < EMB_DIM; d++) v[d] += h[(t * EMB_DIM) + d];
  }
  let norm = 0;
  for (let d = 0; d < EMB_DIM; d++) { v[d] /= (kept || 1); norm += v[d] * v[d]; }
  norm = Math.sqrt(norm) || 1;
  for (let d = 0; d < EMB_DIM; d++) v[d] /= norm;
  return v;
}

/**
 * scoring compares an anchor only against ITS OWN family's threshold — the
 */
async function buildAnchors(anchorTexts) {
  const byFamily = new Map();
  for (const a of anchorTexts) {
    const vector = await embed(a.text);
    if (!byFamily.has(a.family)) byFamily.set(a.family, []);
    byFamily.get(a.family).push({ id: a.id, vector });
  }
  for (const family of byFamily.keys()) {
    if (!Number.isFinite(FT2_FAMILY_THRESHOLDS[family])) {
      throw new Error(`ft2: no calibrated threshold for anchor family "${family}"`);
    }
  }
  return byFamily;
}

/**
 * Scores one window. Returns the deciding family's margin so the caller can log
 * near-band traffic without a second pass.
 *
 * @returns {{fired: boolean, score: number, family: string|null}}
 */
function score(vector, anchorsByFamily) {
  let fired = false;
  let best = -Infinity;
  let bestFamily = null;
  for (const [family, anchors] of anchorsByFamily) {
    const threshold = FT2_FAMILY_THRESHOLDS[family];
    let max = -Infinity;
    for (const a of anchors) {
      let s = 0;
      for (let d = 0; d < EMB_DIM; d++) s += vector[d] * a.vector[d];
      if (s > max) max = s;
    }
    const margin = max - threshold;
    if (margin > best) { best = margin; bestFamily = family; }
    if (max >= threshold) fired = true;
  }
  return { fired, score: best, family: bestFamily };
}

function isLoaded() { return _session !== null && _tokenizer !== null; }

function _resetForTests() { _session = null; _tokenizer = null; }

module.exports = {
  load, embed, buildAnchors, score, isLoaded, verifyIntegrity,
  MODEL_PATH, MODEL_SHA256, EMB_DIM, MAX_LEN, _resetForTests,
};
