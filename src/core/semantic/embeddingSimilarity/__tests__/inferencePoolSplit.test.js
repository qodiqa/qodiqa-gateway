'use strict';

/**
 * (step 10) — inferencePool.embedBatch() splits a long call across workers and returns the vectors in order.
 * Found by the final e2e: a 32 KB prompt (94 windows) ran as ONE task in ONE worker, and 32 KB request semantics
 * went 661 → 1,073 ms p50. Bit-identity of the split with the real
 * model is verify/w9InferenceEquivalence.js IE-05; this suite pins the dispatch contract with a fake worker that
 * returns each text's length as its "vector".
 *
 *   SP-01  > SPLIT_MIN texts on a 4-worker pool → up to 4 tasks, on distinct workers, result in the original order
 *   SP-02  ≤ SPLIT_MIN texts → one task (unchanged)
 *   SP-03  QODIQA_INFERENCE_SPLIT_MIN=0 → one task whatever the length
 *   SP-04  a 1-worker pool never splits
 *   SP-05  one failing chunk fails the whole call (closed), never a partial result
 */

const EventEmitter = require('events');

function fakeWorkerThreads(log, { failOn } = {}) {
  let nextWorker = 0;
  class Worker extends EventEmitter {
    constructor() {
      super(); this.no = nextWorker++;
      setImmediate(() => this.emit('message', { ready: true }));
    }
    postMessage({ id, texts }) {
      log.push({ worker: this.no, n: texts.length, first: texts[0] });
      setImmediate(() => {
        if (failOn && texts.includes(failOn)) this.emit('message', { id, ok: false, error: 'BOOM' });
        else this.emit('message', { id, ok: true, vectors: texts.map((t) => Float64Array.from([t.length])) });
      });
    }
    ref() {} unref() {} terminate() { return Promise.resolve(); }
  }
  return { Worker };
}

function loadPool(env, log, opts) {
  let pool;
  const saved = process.env.QODIQA_INFERENCE_SPLIT_MIN;
  if (env.QODIQA_INFERENCE_SPLIT_MIN === undefined) delete process.env.QODIQA_INFERENCE_SPLIT_MIN; else process.env.QODIQA_INFERENCE_SPLIT_MIN = env.QODIQA_INFERENCE_SPLIT_MIN;
  jest.isolateModules(() => {
    jest.doMock('worker_threads', () => fakeWorkerThreads(log, opts));
    pool = require('../inferencePool');
  });
  if (saved === undefined) delete process.env.QODIQA_INFERENCE_SPLIT_MIN; else process.env.QODIQA_INFERENCE_SPLIT_MIN = saved;
  return pool;
}
const texts = (n) => Array.from({ length: n }, (_, i) => 'x'.repeat(i + 1)); // text i has length i+1

describe('inferencePool split', () => {
  afterEach(() => jest.dontMock('worker_threads'));

  test('SP-01 94 texts on 4 workers → 4 tasks on distinct workers, results in order', async () => {
    const log = []; const pool = loadPool({}, log);
    await pool.start(4);
    const out = await pool.embedBatch(texts(94));
    expect(out.map((v) => v[0])).toEqual(texts(94).map((t) => t.length));
    expect(log).toHaveLength(4);
    expect(new Set(log.map((l) => l.worker)).size).toBe(4);
    expect(log.reduce((a, l) => a + l.n, 0)).toBe(94);
    expect(pool.stats().splitCalls).toBe(1);
    await pool.stop();
  });

  test('SP-02 ≤ SPLIT_MIN texts → one task', async () => {
    const log = []; const pool = loadPool({}, log);
    await pool.start(4);
    expect(pool.SPLIT_MIN).toBe(8);
    const out = await pool.embedBatch(texts(8));
    expect(out.map((v) => v[0])).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(log).toHaveLength(1);
    await pool.stop();
  });

  test('SP-03 QODIQA_INFERENCE_SPLIT_MIN=0 disables the split', async () => {
    const log = []; const pool = loadPool({ QODIQA_INFERENCE_SPLIT_MIN: '0' }, log);
    await pool.start(4);
    await pool.embedBatch(texts(94));
    expect(log).toHaveLength(1);
    await pool.stop();
  });

  test('SP-04 a 1-worker pool never splits', async () => {
    const log = []; const pool = loadPool({}, log);
    await pool.start(1);
    const out = await pool.embedBatch(texts(40));
    expect(out).toHaveLength(40);
    expect(log).toHaveLength(1);
    await pool.stop();
  });

  test('SP-05 one failing chunk fails the whole call', async () => {
    const log = []; const pool = loadPool({}, log, { failOn: 'x'.repeat(60) });
    await pool.start(4);
    await expect(pool.embedBatch(texts(94))).rejects.toThrow('BOOM');
    await pool.stop();
  });
});
