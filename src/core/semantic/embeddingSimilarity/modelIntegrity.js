'use strict';

/**
 * EMBEDDING-MODEL INTEGRITY — the seal for the artifact the whole decision
 * path is calibrated against. ·.
 *
 * WHY THIS EXISTS. Until 2026-08-16 the live decision path embedded through a
 * model that was pulled from HuggingFace on first use into a gitignored
 * `node_modules/@xenova/transformers/.cache`, pinned nowhere. (b)'s Gate 0
 * then established the part that turns untidy into dangerous: our own
 * export+quantize pipeline CANNOT reproduce it — holding runtime and tokenizer
 * fixed, an export of the identical stock weights reaches only
 * mean 0.978446 / min 0.948213 cosine against it.
 *
 * Every calibrated threshold rests on that one artifact:
 *
 *
 * 0.02-class perturbation, roughly 30x. If the cache emptied and HuggingFace
 * served a different revision, the embedding space would shift, every
 * threshold would silently become wrong, and nothing in the system would
 * notice. That silence is the whole problem; this module ends it.
 *
 * FOUR FILES, NOT ONE. Tokenisation shifts embeddings exactly as weights do,
 * so a model-only pin would be false assurance. The tokenizer, its config and
 * the model config are all part of the seal.
 *
 * Structure deliberately mirrors: same
 * fail-loud shape, same "measure before pinning" provenance, same refusal to
 * report a partial pass.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Vendored model root. The repo already commits its two frozen corpora
 * (adversarial-corpus 192 items, bdata-wildguardmix at 37.5 MB) on exactly
 * this logic — a measurement is only as trustworthy as the artifact it was
 * taken against. B-1's "weights are cached, not committed" applied to 39 MB of
 * experiment weights for cross-encoders that were then abandoned; this is a
 * calibration artifact the shipped decision path rests on. That is a
 * distinction B-1 had no reason to draw, not a reversal of its decision.
 */
const MODEL_DIR = path.join(__dirname, '..', '..', '..', '..', 'eval', 'embedding-model');
const MODEL_ID = 'Xenova/all-MiniLM-L6-v2';

/**
 * sha256 of each vendored file, measured from the artifact the live path was
 * actually running when every threshold in this system was calibrated.
 */
const PINNED = Object.freeze({
  'onnx/model_quantized.onnx': 'afdb6f1a0e45b715d0bb9b11772f032c399babd23bfc31fed1c170afc848bdb1',
  'tokenizer.json':            'da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0',
  'tokenizer_config.json':     '9261e7d79b44c8195c1cada2b453e55b00aeb81e907a6664974b4d7776172ab3',
  'config.json':               '7135149f7cffa1a573466c6e4d8423ed73b62fd2332c575bf738a0d033f70df7',
});

function modelRoot() {
  return path.join(MODEL_DIR, ...MODEL_ID.split('/'));
}

/**
 * Verifies every pinned file. Returns a structured result rather than
 * throwing, so the boot path can fail closed with a reason and the CLI can
 * print a full report instead of dying on the first mismatch.
 *
 * @returns {{ok: boolean, checked: number, failures: string[], files: Array<{file: string, ok: boolean, expected: string, actual: string|null, bytes: number|null}>}}
 */
function verifyModelIntegrity() {
  const root = modelRoot();
  const files = [];
  const failures = [];

  for (const [rel, expected] of Object.entries(PINNED)) {
    const full = path.join(root, rel);
    let actual = null;
    let bytes = null;
    try {
      const buf = fs.readFileSync(full);
      bytes = buf.length;
      actual = crypto.createHash('sha256').update(buf).digest('hex');
    } catch (err) {
      failures.push(`${rel}: unreadable (${(err && err.code) || 'unknown'})`);
      files.push({ file: rel, ok: false, expected, actual: null, bytes: null });
      continue;
    }
    const ok = actual === expected;
    if (!ok) failures.push(`${rel}: sha256 ${actual} != pinned ${expected}`);
    files.push({ file: rel, ok, expected, actual, bytes });
  }

  return { ok: failures.length === 0, checked: files.length, failures, files };
}

let _cached = null;

/**
 * Memoised per process.
 *
 * The full check reads 23.69 MB — measured at 66.5ms median. Production boots
 * once and pays that once, but tests call init() repeatedly and re-hashing
 * every time would add real minutes to the suite for no safety, since the
 * artifact cannot change mid-process in any way this guard could act on.
 *
 * SCOPE, stated so nothing downstream assumes more than is here: this verifies
 * PROVENANCE ONCE AT BOOT. It is deliberately NOT a runtime anti-tamper guard
 * — it does not detect mid-process corruption of an already-loaded model, and
 * nothing should be built on the assumption that it would.
 */
function verifyModelIntegrityOnce() {
  if (_cached === null) _cached = verifyModelIntegrity();
  return _cached;
}

// Test-only: drops the memoised verdict so a test can simulate a fresh boot
// against altered files — mirrors embeddingBackend's _resetForTests() pattern.
function _resetIntegrityCacheForTests() {
  _cached = null;
}

module.exports = {
  verifyModelIntegrity,
  verifyModelIntegrityOnce,
  _resetIntegrityCacheForTests,
  PINNED,
  MODEL_DIR,
  MODEL_ID,
  modelRoot,
};
