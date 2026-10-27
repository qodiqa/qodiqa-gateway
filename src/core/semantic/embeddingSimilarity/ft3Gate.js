'use strict';

/**
 * FT-3 — THE SIXTH GATE (fine-tune v2).
 *
 * A second contrastively fine-tuned all-MiniLM-L6-v2, trained on VAL-C2's
 * roleplay/persona miss set to attack the style weakness VAL-C2 measured
 * scored as anchor similarity in ITS OWN embedding space against per-family
 * thresholds derived by the same held-out calibration protocol FT-2 uses.
 *
 * DEFAULT ON since THE SWAP: `QODIQA_SEM_FT3_ENABLED` defaults to
 * true (config.js) and FT-3 is the live fine-tuned gate in FT-2's former slot.
 * (This comment previously said "shipped disabled", which described the
 * 2026-08-19 wiring commit, before the swap — corrected 2026-10-14, launch plan
 * R-17.) When the flag is false nothing in this module is loaded, embedded or
 * executed — index.js's init() skips the load entirely; production refuses a
 * non-default value of the flag (bootValidator.js).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE MEASURED CASE FOR SHIPPING IT AS A CANDIDATE, and the honest limit.
 *
 *
 * CANDIDATE on the strength of the three unambiguous passes, not because the
 * catastrophic forgetting on the style this training did not target.
 *
 * WHY fp32 AND NOT fp16, identical reasoning to ft2Gate.js: fp16 has no native
 * CPU kernels in onnxruntime, so it runs ~2x slower. Measured on this
 * checkpoint: fp16 encoder p95 22.7ms. Thresholds below were DERIVED on fp16
 * and are SERVED on fp32, verified at ZERO decision flips across all 2,281
 * held-out items (|margin delta| mean 8.312e-5 / max 3.338e-4) — the same
 * check FT-2 itself passed before shipping.
 *
 * WHY intraOpNumThreads=1: inherited from ft2Gate.js's own measurement (fp32
 * loaded p95 64.48ms at 1 thread against 78.71ms at the default under
 * contention). Not re-measured for FT-3; the reason is a property of the
 * runtime under contention, not of the weights.
 *
 * FAIL-CLOSED, mirroring every other gate here and ../index.js's
 * _denyEngineFailure(): any load or inference failure surfaces as a DENY
 * through index.js, never as a silent ALLOW and never as a throw.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { FT3_FAMILY_THRESHOLDS, FT3_SESSION_INTRA_OP_THREADS } = require('./config');

/**
 * Vendored served artifact, same rationale and same location convention as
 * FT-2's: a calibrated threshold is meaningless without the exact bytes it was
 * calibrated against.
 *
 * COST DISCLOSED, and it is not small: 90,376,758 bytes, the same size as
 * FT-2's own artifact, taking this repository's vendored-model footprint to
 * roughly 180 MB. REPO-SIZE is an already-open finding against FT-2's 90 MB
 * alone. This doubles it, knowingly, for a gate that is DISABLED — the
 * alternative (gitignoring it) was rejected because a hash-pinned gate whose
 * artifact is absent from a fresh clone fails confusingly the moment anyone
 * flips the flag.
 */
const MODEL_PATH = path.join(__dirname, '..', '..', '..', '..', 'eval', 'finetune-v2', 'served', 'ft3_fp32.onnx');
const MODEL_SHA256 = '0b9004911823b8cf7994da6128a03307ae5cfd2f4c881a721e957d021e14c2e1';

/**
 * TOKENIZER. Shared with the frozen model and with FT-2, deliberately NOT a
 * third vendored copy — FT-3 is a fine-tune of all-MiniLM-L6-v2 and
 * fine-tuning does not touch the vocabulary. Same argument ft2Gate.js records.
 */
const MAX_LEN = 256;
const EMB_DIM = 384;

let _session = null;
let _tokenizer = null;

function verifyIntegrity() {
  if (!fs.existsSync(MODEL_PATH)) {
    return { ok: false, reason: `ft3 model missing at ${path.relative(process.cwd(), MODEL_PATH)}` };
  }
  const actual = crypto.createHash('sha256').update(fs.readFileSync(MODEL_PATH)).digest('hex');
  if (actual !== MODEL_SHA256) {
    return { ok: false, reason: `ft3 model sha256 ${actual.slice(0, 16)}… != pinned ${MODEL_SHA256.slice(0, 16)}…` };
  }
  return { ok: true, bytes: fs.statSync(MODEL_PATH).size };
}

/**
 * Loads the ONNX session and the shared tokenizer. Called from init() ONLY when
 * the flag is on, so a disabled gate costs nothing at boot.
 */
async function load() {
  const integrity = verifyIntegrity();
  if (!integrity.ok) throw new Error(`ft3 gate integrity: ${integrity.reason}`);

  const ort = require('onnxruntime-node');
  _session = await ort.InferenceSession.create(MODEL_PATH, {
    intraOpNumThreads: FT3_SESSION_INTRA_OP_THREADS,
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
 * Mean-pools and L2-normalises one text into FT-3 space. Identical arithmetic
 * to ft2Gate.embed() and to the calibration harness — mean over unmasked
 * positions, then normalise.
 */
// (D4): the server runs this in a worker (./inferencePool.js); every worker runs embedInProcess() itself, so
// the vector is produced by this exact code either way. Transferred as Float64Array: exact.
async function embed(text) {
  const memo = require('./embedMemo'); // step 6: per-stream memo; undefined outside a stream
  const hit = memo.get('ft3', text);
  if (hit !== undefined) return hit;
  const pool = require('./inferencePool');
  const v = pool.enabled() ? (await pool.ft3Embed([text]))[0] : await embedInProcess(text);
  memo.set('ft3', text, v);
  return v;
}

async function embedInProcess(text) {
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
    if (!Number.isFinite(FT3_FAMILY_THRESHOLDS[family])) {
      throw new Error(`ft3: no calibrated threshold for anchor family "${family}"`);
    }
  }
  return byFamily;
}

/**
 * Scores one window. Returns the deciding family's margin so the caller can log
 * near-band traffic without a second pass. Identical shape to ft2Gate.score().
 *
 * @returns {{fired: boolean, score: number, family: string|null}}
 */
function score(vector, anchorsByFamily) {
  let fired = false;
  let best = -Infinity;
  let bestFamily = null;
  for (const [family, anchors] of anchorsByFamily) {
    const threshold = FT3_FAMILY_THRESHOLDS[family];
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
  load, embed, embedInProcess, buildAnchors, score, isLoaded, verifyIntegrity,
  MODEL_PATH, MODEL_SHA256, EMB_DIM, MAX_LEN, _resetForTests,
};
