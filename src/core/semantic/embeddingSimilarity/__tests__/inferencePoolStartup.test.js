'use strict';

/**
 * regression — inference workers must be started ONE AT A TIME.
 * Concurrent onnxruntime session creation across worker threads crashed the server with 0xC0000374
 * STATUS_HEAP_CORRUPTION. After serializing the
 *
 *   PS-01  worker i+1 is constructed only after worker i reported { ready: true }
 *   PS-02  a worker that fails to load aborts the start and terminates every worker already created
 *   PS-03  a task is dispatched to the least-busy worker and resolves to plain number arrays
 */

const { EventEmitter } = require('events');

function fakeWorkers(behaviour) {
  const created = [];
  class FakeWorker extends EventEmitter {
    constructor() {
      super();
      this.i = created.length; created.push(this);
      this.terminated = false;
      this.posted = [];
      setImmediate(() => this.emit('message', behaviour(this.i)));
    }
    postMessage(m) { this.posted.push(m); setImmediate(() => this.emit('message', { id: m.id, ok: true, vectors: m.texts.map(() => Float64Array.from([this.i, 0.5])) })); }
    terminate() { this.terminated = true; return Promise.resolve(0); }
    ref() {} unref() {}
  }
  return { FakeWorker, created };
}

describe('inference pool start-up is serialized', () => {
  afterEach(() => { jest.resetModules(); jest.dontMock('worker_threads'); });

  test('PS-01 worker i+1 is created only after worker i is ready', async () => {
    const readyAt = []; const createdWhileNotReady = [];
    const { FakeWorker, created } = fakeWorkers((i) => { readyAt[i] = true; return { ready: true }; });
    const Orig = FakeWorker;
    class Checked extends Orig { constructor() { const pendingBefore = created.filter((w, j) => !readyAt[j]).length; super(); if (pendingBefore) createdWhileNotReady.push(this.i); } }
    jest.doMock('worker_threads', () => ({ Worker: Checked }));
    const pool = require('../inferencePool');
    await pool.start(4);
    expect(created.length).toBe(4);
    expect(createdWhileNotReady).toEqual([]);
    await pool.stop();
  });

  test('PS-02 a failing worker aborts start and terminates the workers already created', async () => {
    const { FakeWorker, created } = fakeWorkers((i) => (i === 2 ? { ready: false, error: 'boom' } : { ready: true }));
    jest.doMock('worker_threads', () => ({ Worker: FakeWorker }));
    const pool = require('../inferencePool');
    await expect(pool.start(4)).rejects.toThrow(/worker 2 failed to load: boom/);
    expect(created.length).toBe(3); // the 4th was never created
    expect(created.every((w) => w.terminated)).toBe(true);
    expect(pool.enabled()).toBe(false);
  });

  test('PS-03 dispatch to the least-busy worker; results are plain arrays', async () => {
    const { FakeWorker } = fakeWorkers(() => ({ ready: true }));
    jest.doMock('worker_threads', () => ({ Worker: FakeWorker }));
    const pool = require('../inferencePool');
    await pool.start(2);
    const [a, b] = await Promise.all([pool.embedBatch(['x']), pool.embedBatch(['y'])]);
    expect(Array.isArray(a[0])).toBe(true);
    expect([a[0][0], b[0][0]].sort()).toEqual([0, 1]); // one task per worker
    expect(pool.stats()).toMatchObject({ size: 2, queued: 0 });
    await pool.stop();
  });
});
