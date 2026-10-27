'use strict';

// hash-link ordering — the chain order is defined by links, not seq.

const { orderByHashLinks, createStreamingLinker } = require('../hashLinkOrder');

function chain(n) {
  const rows = [];
  let prev = 'GENESIS';
  for (let i = 1; i <= n; i++) { const hash = `h${i}`; rows.push({ seq: i, hash, prevHash: prev }); prev = hash; }
  return rows;
}
const swapSeqAt = (rows, i) => { const r = rows.map((x) => ({ ...x })); [r[i], r[i + 1]] = [r[i + 1], r[i]]; return r; };

describe('orderByHashLinks (all-or-nothing)', () => {
  test('an in-order chain is returned unchanged, reordered 0', () => {
    const rows = chain(5);
    const r = orderByHashLinks(rows);
    expect(r).toMatchObject({ linked: true, reordered: 0 });
    expect(r.rows.map((x) => x.hash)).toEqual(['h1', 'h2', 'h3', 'h4', 'h5']);
  });

  test('a seq inversion is put back in link order', () => {
    const r = orderByHashLinks(swapSeqAt(chain(6), 2));
    expect(r.linked).toBe(true);
    expect(r.reordered).toBe(2);
    expect(r.rows.map((x) => x.hash)).toEqual(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
  });

  test('a broken chain (orphan) is returned UNCHANGED so the downstream walk still reports it', () => {
    const rows = chain(4); rows[2] = { ...rows[2], prevHash: 'missing' };
    const r = orderByHashLinks(rows);
    expect(r.linked).toBe(false);
    expect(r.rows).toBe(rows);
  });

  test('a fork (two rows with the same prevHash) is returned unchanged', () => {
    const rows = chain(3); rows.push({ seq: 4, hash: 'fork', prevHash: 'h2' });
    expect(orderByHashLinks(rows).linked).toBe(false);
  });

  test('empty input', () => {
    expect(orderByHashLinks([])).toMatchObject({ linked: true, reordered: 0, rows: [] });
  });
});

describe('createStreamingLinker (paginated walk)', () => {
  test('in-order batches pass straight through, no inversions', () => {
    const rows = chain(6); const l = createStreamingLinker();
    expect([...l.push(rows.slice(0, 3)), ...l.push(rows.slice(3))].map((x) => x.hash)).toEqual(rows.map((x) => x.hash));
    expect(l.pending()).toEqual([]);
    expect(l.inversions()).toBe(0);
    expect(l.cursor()).toBe('h6');
  });

  test('a child arriving before its parent — even across a batch boundary — is held, then linked', () => {
    const rows = swapSeqAt(chain(6), 2); // seq order: h1 h2 h4 h3 h5 h6
    const l = createStreamingLinker();
    const out = [...l.push(rows.slice(0, 3)), ...l.push(rows.slice(3))];
    expect(out.map((x) => x.hash)).toEqual(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
    expect(l.pending()).toEqual([]);
    expect(l.inversions()).toBe(1);
  });

  test('a row whose parent never arrives stays pending (a real break is never hidden)', () => {
    const rows = chain(4); rows[2] = { ...rows[2], prevHash: 'missing' };
    const l = createStreamingLinker();
    l.push(rows);
    // h3's parent is missing, so h3 AND everything after it (h4) stay unlinked
    expect(l.pending().map((x) => x.hash).sort()).toEqual(['h3', 'h4']);
  });

  test('a resumed walk starts from the watermark hash', () => {
    const rows = chain(5); const l = createStreamingLinker('h2');
    expect(l.push(rows.slice(2)).map((x) => x.hash)).toEqual(['h3', 'h4', 'h5']);
  });

  test('a fork throws HASH_LINK_FORK', () => {
    const l = createStreamingLinker();
    expect(() => l.push([{ hash: 'a', prevHash: 'x' }, { hash: 'b', prevHash: 'x' }])).toThrow(expect.objectContaining({ code: 'HASH_LINK_FORK' }));
  });

  test('the pending set is bounded', () => {
    const l = createStreamingLinker('GENESIS', { maxPending: 2 });
    expect(() => l.push([{ hash: 'a', prevHash: 'p1' }, { hash: 'b', prevHash: 'p2' }, { hash: 'c', prevHash: 'p3' }]))
      .toThrow(expect.objectContaining({ code: 'HASH_LINK_PENDING_OVERFLOW' }));
  });
});
