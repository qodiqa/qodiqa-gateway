'use strict';

/**
 * per-stream embedding memo (../embedMemo.js).
 * (The real-model proof that decisions and blocking points are unchanged is
 * npm run test:stream-equivalence — 815 streams identical)
 *
 *   EM-01  outside run() nothing is cached (no memo leaks into non-stream classification)
 *   EM-02  inside run() a stored vector is returned (as a copy — callers cannot mutate the cache)
 *   EM-03  two concurrent streams never share a memo
 *   EM-04  LRU bound: past `max` the least-recently-used entry is evicted
 *   EM-05  MiniLM and FT-3 vectors are cached separately (same text, different model)
 */

const memo = require('../embedMemo');

describe('embedMemo', () => {
  test('EM-01 no caching outside a stream scope', () => {
    memo.set('minilm', 'a', [1, 2]);
    expect(memo.get('minilm', 'a')).toBeUndefined();
    expect(memo.current()).toBeNull();
  });

  test('EM-02 cached inside a scope, returned as a copy', async () => {
    const m = memo.create();
    await memo.run(m, async () => {
      memo.set('minilm', 'a', [1, 2]);
      const v = memo.get('minilm', 'a');
      expect(v).toEqual([1, 2]);
      v[0] = 99;
      expect(memo.get('minilm', 'a')).toEqual([1, 2]);
    });
    expect(m.hits).toBe(2);
  });

  test('EM-03 concurrent streams are isolated', async () => {
    const a = memo.create(); const b = memo.create();
    await Promise.all([
      memo.run(a, async () => { memo.set('minilm', 'x', [1]); await new Promise((r) => setImmediate(r)); expect(memo.get('minilm', 'x')).toEqual([1]); }),
      memo.run(b, async () => { await new Promise((r) => setImmediate(r)); expect(memo.get('minilm', 'x')).toBeUndefined(); }),
    ]);
  });

  test('EM-04 LRU eviction at the bound', async () => {
    const m = memo.create(2);
    await memo.run(m, async () => {
      memo.set('minilm', 'a', [1]); memo.set('minilm', 'b', [2]);
      memo.get('minilm', 'a'); // a is now most recent
      memo.set('minilm', 'c', [3]); // evicts b
      expect(memo.get('minilm', 'b')).toBeUndefined();
      expect(memo.get('minilm', 'a')).toEqual([1]);
      expect(memo.get('minilm', 'c')).toEqual([3]);
    });
  });

  test('EM-05 per-model caches', async () => {
    const m = memo.create();
    await memo.run(m, async () => {
      memo.set('minilm', 't', [1]);
      expect(memo.get('ft3', 't')).toBeUndefined();
      memo.set('ft3', 't', [2]);
      expect(memo.get('minilm', 't')).toEqual([1]);
      expect(memo.get('ft3', 't')).toEqual([2]);
    });
  });
});
