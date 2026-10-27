'use strict';

/**
 * Production embedding backend for SEM-C's embedding-similarity classifier.
 *
 * In-process ONNX inference via @xenova/transformers — no network calls once
 * the model is cached on disk (see __tests__/noNetwork.test.js, promoted from
 *'s D3 proof). Interface mirrors
 *'s embedOne()/cosineSim() so the spike's
 * measured numbers (SESSION-1B-FINDINGS.md) remain representative of this
 * module's actual behavior; the spike itself stays unwired, throwaway code.
 */

const path = require('path');
const { MODEL_DIR } = require('./modelIntegrity');
const memo = require('./embedMemo');

const MODEL = 'Xenova/all-MiniLM-L6-v2';

// the pinned file the pipeline itself loads (modelIntegrity.js pins its sha256).
const MODEL_FILE = path.join(MODEL_DIR, 'Xenova', 'all-MiniLM-L6-v2', 'onnx', 'model_quantized.onnx');

// the session the pipeline runs on. transformers.js builds its own with runtime-default threads, which
// claimed every core: 43-46 ms of CPU per ~2 ms embed, 22.7-23.0 cores busy. The
// audit found that passing session_options through pipeline() did not take effect. What does take effect is
// replacing ONLY model.session with a session built by the SAME onnxruntime-node class from the SAME pinned file —
// tokenizer, pooling and normalisation stay the pipeline's own code: 46.49 -> 2.04 ms CPU per embed, vectors
// bit-identical. ft2Gate.js/ft3Gate.js already run this way.
// At one thread onnxruntime computes on the CALLING thread, which is why the server runs inference in the worker
// pool (./inferencePool.js) instead of on the main thread.
const SESSION_OPTIONS = Object.freeze({ intraOpNumThreads: 1, interOpNumThreads: 1, executionMode: 'sequential' });

let _extractor = null;
let _pool = null; // ./inferencePool.js once enablePool() has started it (server only); null = in-process

/**
 * Loads and caches the feature-extraction pipeline. Callers (index.js's
 * init()) are required to await this once at boot rather than relying on
 * implicit first-call lazy loading — a request must never be the trigger for
 * a multi-hundred-millisecond (or, on a cold cache, multi-second) model load.
 */
async function loadModel() {
  if (_extractor) return _extractor;
  // Dynamic import, not require(): @xenova/transformers ships "type":
  // "module" (pure ESM, no CJS build) — a synchronous require() of it fails
  // under Jest's module runtime (which does not implement Node's newer
  // require(esm) interop the way a plain `node` process does), even though
  // it happens to work outside Jest. Dynamic import() is valid syntax in a
  // CommonJS file and Node's native loader handles the ESM interop
  // correctly in both contexts.
  const { pipeline, env } = await import('@xenova/transformers');

  // · read the VENDORED, hash-pinned artifact. Never the
  // HuggingFace cache, never the network.
  //
  // Without this the integrity check in ../index.js would hash files the
  // decision path does not open — a decorative pin. The load proof
  // closed the network and pointed
  // the cache at a nonexistent directory, and the load still produced
  // bit-identical vectors (max|delta| 0.000e+0), which is what makes the pin
  // guard the file actually read here.
  //
  // allowRemoteModels=false is load-bearing, not tidiness: a missing vendored
  // file must fail LOUDLY rather than silently re-fetch a different upstream
  // 0.838629 and V9 0.688841 are all calibrated in. Note this is module-global
  // to @xenova/transformers — an unwired spike that wants to fetch a model
  // (e.g. B-1's cross-encoders) must set it back itself.
  env.localModelPath = MODEL_DIR;
  env.allowLocalModels = true;
  env.allowRemoteModels = false;

  const extractor = await pipeline('feature-extraction', MODEL);
  const ort = require('onnxruntime-node');
  const original = extractor.model.session;
  const single = await ort.InferenceSession.create(MODEL_FILE, SESSION_OPTIONS);
  // Same runtime class and the same graph contract, or refuse: a different build or model could embed differently.
  if (Object.getPrototypeOf(single).constructor !== Object.getPrototypeOf(original).constructor
    || JSON.stringify(single.inputNames) !== JSON.stringify(original.inputNames)
    || JSON.stringify(single.outputNames) !== JSON.stringify(original.outputNames)) {
    throw new Error('embeddingBackend: single-thread session does not match the pipeline session contract');
  }
  extractor.model.session = single;
  _extractor = extractor;
  return _extractor;
}

/**
 * (D4): runs inference in a pool of worker threads from now on (server startup only). Each worker runs this
 * module in in-process mode — identical code, identical vectors. Idempotent; n = 0 leaves in-process mode.
 */
async function enablePool(n) {
  if (!n) return 0;
  const pool = require('./inferencePool');
  await pool.start(n);
  _pool = pool;
  return n;
}
function poolStats() { return _pool ? _pool.stats() : { size: 0 }; }

/**
 * @param {string} text
 * @returns {Promise<number[]>} a 384-dim, L2-normalized embedding vector
 */
async function embed(text) {
  const hit = memo.get('minilm', text); // step 6: per-stream memo (./embedMemo.js); undefined outside a stream
  if (hit !== undefined) return hit;
  const v = _pool ? (await _pool.embedBatch([text]))[0] : await embedInProcess(text);
  memo.set('minilm', text, v);
  return v;
}

async function embedInProcess(text) {
  if (!_extractor) {
    throw new Error('embeddingBackend.embed() called before loadModel() completed');
  }
  const output = await _extractor(text, { pooling: 'mean', normalize: true });
  return Array.from(output.data);
}

/**
 * (step 3): every text of one call (all windows of one classified text) in ONE task. In the pool this is one
 * message to one worker; in-process it is the same per-text embed, in order. Vectors are identical to embed().
 */
async function embedBatch(texts) {
  // step 6: inside a stream's memo scope, only the texts not embedded yet in this stream are computed (still in
  // ONE call); a memoized vector is the identical vector (embedding is deterministic).
  const out = texts.map((t) => memo.get('minilm', t));
  const missIdx = []; for (let i = 0; i < texts.length; i++) if (out[i] === undefined) missIdx.push(i);
  if (missIdx.length) {
    const miss = missIdx.map((i) => texts[i]);
    const vs = _pool ? await _pool.embedBatch(miss) : await embedBatchInProcess(miss);
    missIdx.forEach((i, k) => { out[i] = vs[k]; memo.set('minilm', texts[i], vs[k]); });
  }
  return out;
}
async function embedBatchInProcess(texts) {
  const out = [];
  for (const t of texts) out.push(await embedInProcess(t)); // eslint-disable-line no-await-in-loop
  return out;
}

function cosineSim(a, b) {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

function isLoaded() {
  return _extractor !== null;
}

// Test-only: drops the cached extractor so a test can force the next
// loadModel()/embed() call to behave as freshly booted, without needing to
// actually corrupt the ONNX runtime — mirrors classifierRegistry.js's
// _forceDiscoveryErrorForTests()/_resetDiscoveryForTests() pattern.
function _resetForTests() {
  _extractor = null;
}

module.exports = {
  loadModel, embed, embedBatch, embedInProcess, embedBatchInProcess, enablePool, poolStats,
  cosineSim, isLoaded, MODEL, SESSION_OPTIONS, _resetForTests,
};
