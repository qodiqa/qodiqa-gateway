'use strict';

/**
 * bounded pool of inference workers (./inferenceWorker.js).
 *
 * Why a pool at all: at intraOpNumThreads=1 onnxruntime-node computes on the CALLING thread, so the single-threaded
 * session that cut CPU per embed from ~45 ms to ~2 ms would block
 * the event loop if it ran on the main thread. N workers = N cores of inference, off the main thread.
 *
 * Dispatch: least-busy worker. Every task carries all the texts of one call (all windows of a text = ONE task).
 * Queue: bounded (QUEUE_MAX tasks in flight + waiting across the pool); beyond it a task is rejected with
 * INFERENCE_QUEUE_FULL, which the classifier turns into its existing fail-closed DENY. Admission control
 * (src/api/admission.js) keeps load far below this safety bound; the bound exists so memory can never grow without
 * limit. Workers are unref()'d so a CLI process can exit.
 */

const path = require('path');
const { Worker } = require('worker_threads');

const QUEUE_MAX = 10_000;

let _workers = null;   // [{ worker, busy, ready }]
let _pending = new Map();
let _nextId = 1;
let _queued = 0;
let _stats = { tasks: 0, texts: 0, rejected: 0 };

function size() { return _workers ? _workers.length : 0; }
function enabled() { return size() > 0; }

async function start(n) {
  if (_workers) return size();
  if (!Number.isInteger(n) || n < 1) throw new Error(`inferencePool.start: size must be a positive integer, got ${n}`);
  const script = path.join(__dirname, 'inferenceWorker.js');
  const ws = [];
  const ready = [];
  for (let i = 0; i < n; i++) {
    const w = new Worker(script);
    const slot = { worker: w, busy: 0, ready: false };
    ready.push(new Promise((resolve, reject) => {
      const onFirst = (m) => {
        if (m && m.ready === true) { slot.ready = true; resolve(); }
        else if (m && m.ready === false) reject(new Error(`inference worker ${i} failed to load: ${m.error}`));
        else return; // not the handshake
        w.off('message', onFirst);
      };
      w.on('message', onFirst);
      w.once('error', reject);
    }));
    w.on('message', (m) => {
      if (!m || m.id === undefined) return;
      const p = _pending.get(m.id);
      if (!p) return;
      _pending.delete(m.id);
      slot.busy--; _queued--; _idleCheck();
      if (m.ok) p.resolve(m.vectors.map((v) => Array.from(v)));
      else p.reject(new Error(m.error || 'INFERENCE_WORKER_ERROR'));
    });
    w.on('error', (err) => {
      // A crashed worker fails every task it held — closed, never silently dropped.
      for (const [id, p] of _pending) if (p.slot === slot) { _pending.delete(id); _queued--; p.reject(err); }
      _idleCheck();
      slot.busy = Number.POSITIVE_INFINITY;
    });
    ws.push(slot); // ref'd while loading; unref'd once idle (below)
    // workers are started ONE AT A TIME — the next worker is created only after this one has built its
    // onnxruntime sessions. Concurrent session creation across worker threads crashed the process with
    // 0xC0000374 STATUS_HEAP_CORRUPTION.
    try { await ready[ready.length - 1]; } catch (err) { _workers = ws; await stop(); throw err; }
  }
  _workers = ws;
  //
  _idleCheck();
  return n;
}

// Workers are unref()'d while idle so a CLI process can exit, and ref()'d while any task is pending so a process
// awaiting only an inference result is not ended under it.
function _idleCheck() { if (_queued === 0 && _workers) for (const s of _workers) s.worker.unref(); }

function _run(op, texts) {
  if (!_workers) return Promise.reject(new Error('INFERENCE_POOL_NOT_STARTED'));
  if (_queued >= QUEUE_MAX) { _stats.rejected++; return Promise.reject(new Error('INFERENCE_QUEUE_FULL')); }
  let slot = _workers[0];
  for (const s of _workers) if (s.busy < slot.busy) slot = s;
  const id = _nextId++;
  slot.busy++; _queued++;
  if (_queued === 1) for (const s of _workers) s.worker.ref(); // keep the process alive while a task is pending
  _stats.tasks++; _stats.texts += texts.length;
  return new Promise((resolve, reject) => {
    _pending.set(id, { resolve, reject, slot });
    slot.worker.postMessage({ id, op, texts });
  });
}

// (step 10): a call with more than SPLIT_MIN texts (a long text's windows: 32 KB ≈ 94) is split into up to
// size() contiguous chunks, one task each — least-busy dispatch spreads them over the workers — and the vectors are
// concatenated back in order. Found by the final e2e: one 94-window task ran single-threaded in ONE worker while the
// others idled, and 32 KB request semantics went 661 → 1,073 ms p50.
// Every worker holds the identical pinned session, so the vectors are bit-identical to the unsplit call
// (verify/w9InferenceEquivalence.js IE-05). QODIQA_INFERENCE_SPLIT_MIN=0 disables the split.
const SPLIT_MIN = (() => { const v = parseInt(process.env.QODIQA_INFERENCE_SPLIT_MIN, 10); return Number.isFinite(v) && v >= 0 ? v : 8; })();

/** Embeds the texts of one call (split across workers when long); resolves to plain number arrays, in order,
 *  bit-identical to in-process. */
async function embedBatch(texts) {
  const n = size();
  if (SPLIT_MIN === 0 || n < 2 || texts.length <= SPLIT_MIN) return _run('embedBatch', texts);
  const parts = Math.min(n, Math.ceil(texts.length / SPLIT_MIN));
  const per = Math.ceil(texts.length / parts);
  const chunks = [];
  for (let i = 0; i < texts.length; i += per) chunks.push(texts.slice(i, i + per));
  _stats.splitCalls = (_stats.splitCalls || 0) + 1;
  const results = await Promise.all(chunks.map((c) => _run('embedBatch', c)));
  return results.flat();
}
/** FT-3 vectors for the given texts, computed by ft3Gate's own code inside a worker. */
function ft3Embed(texts) { return _run('ft3Embed', texts); }

async function stop() {
  const ws = _workers || [];
  _workers = null;
  for (const [, p] of _pending) p.reject(new Error('INFERENCE_POOL_STOPPED'));
  _pending = new Map(); _queued = 0;
  await Promise.all(ws.map((s) => s.worker.terminate().catch(() => {})));
}

function stats() {
  return { size: size(), queued: _queued, inFlightPerWorker: (_workers || []).map((s) => s.busy), ...(_stats), queueMax: QUEUE_MAX };
}

module.exports = { start, stop, enabled, size, embedBatch, ft3Embed, stats, QUEUE_MAX, SPLIT_MIN };
