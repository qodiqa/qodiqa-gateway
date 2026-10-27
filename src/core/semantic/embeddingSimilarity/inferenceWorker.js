'use strict';

/**
 * one inference worker of the pool in ./inferencePool.js.
 *
 * Runs the SAME code the main thread would: ./embeddingBackend.js in in-process mode (its loadModel() builds the
 * pinned MiniLM pipeline and swaps in the single-threaded ONNX session) and ./ft3Gate.js (its own pinned,
 * single-threaded session). The main thread keeps all scoring, gating and window selection; a worker only turns
 * texts into vectors. Identical code on identical inputs → identical vectors (proven by
 * against the frozen baseline).
 *
 * Messages in:  { id, op: 'embedBatch' | 'ft3Embed', texts: string[] }
 * Messages out: { id, ok: true, vectors: Float64Array[] } (Float64 = exact for both the float32 MiniLM output and FT-3's float64 pooling) | { id, ok: false, error }
 * First message out: { ready: true } once the models are loaded, or { ready: false, error }.
 */

const { parentPort } = require('worker_threads');
const backend = require('./embeddingBackend');

let _ft3Loaded = null;
async function ft3() {
  if (!_ft3Loaded) {
    const g = require('./ft3Gate');
    _ft3Loaded = g.load().then(() => g);
  }
  return _ft3Loaded;
}

(async () => {
  try {
    await backend.loadModel();
    if (require('./config').FT3_ENABLED) await ft3(); // every onnxruntime session this worker will ever use is built NOW, during the serialized
    //            start-up, never lazily on a request (no concurrent native session creation, ever)
    parentPort.postMessage({ ready: true });
  } catch (err) {
    parentPort.postMessage({ ready: false, error: err && err.message ? err.message : String(err) });
    return;
  }
  parentPort.on('message', async (msg) => {
    const { id, op, texts } = msg || {};
    try {
      const vectors = [];
      if (op === 'embedBatch') {
        for (const v of await backend.embedBatchInProcess(texts)) vectors.push(Float64Array.from(v));
      } else if (op === 'ft3Embed') {
        const g = await ft3();
        for (const t of texts) vectors.push(Float64Array.from(await g.embedInProcess(t)));
      } else {
        throw new Error(`unknown op ${op}`);
      }
      parentPort.postMessage({ id, ok: true, vectors }, vectors.map((v) => v.buffer));
    } catch (err) {
      parentPort.postMessage({ id, ok: false, error: err && err.message ? err.message : String(err) });
    }
  });
})();
