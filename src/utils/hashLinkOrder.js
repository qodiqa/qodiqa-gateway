'use strict';

/**
 * Hash-link ordering for audit-chain rows.
 *
 * The audit chain's order is defined by hash links (each row's prevHash names
 * its parent; the first row names 'GENESIS'), never by the PostgreSQL `seq`
 * column., the single-node PG mirror could commit rows out of chain
 * order, and historical mirrors still carry those seq inversions, so every
 * consumer that walks the chain must follow links, not seq. Pure functions,
 * no I/O — shared by src/infra/postgres/pg-audit-backend.js
 * (loadChainFromPg) and src/core/audit/verifier/ChainVerifier.js (batched walk).
 *
 *   orderByHashLinks(rows, { start })
 *     All-or-nothing, same contract as mirrorConsistencyCheck._reorderByHashChain:
 *     if `rows` form exactly one linear chain starting at `start` (default
 *     'GENESIS'), returns them in link order with `reordered` = number of rows
 *     whose position changed; otherwise returns them UNCHANGED (seq order) so
 *     a downstream verifying walk still reports the real break exactly as
 *     before.
 *
 *   createStreamingLinker(startHash, { maxPending })
 *     For paginated walks (rows arrive in seq order, batch by batch). push(rows)
 *     returns the rows that are now linkable, in link order; a row whose parent
 *     has not been seen yet is held (bounded by maxPending) until its parent
 *     arrives. pending() is what is still unlinked — empty at the end of a
 *     complete, valid chain; non-empty means a real break (orphan/fork).
 *     inversions() counts rows that arrived before their parent (historical
 *     seq inversions tolerated by the walk).
 */

function orderByHashLinks(rows, { start = 'GENESIS' } = {}) {
  if (!Array.isArray(rows) || rows.length === 0) return { rows: rows || [], linked: true, reordered: 0 };
  const byPrev = new Map();
  for (const r of rows) {
    if (!r || typeof r.prevHash !== 'string' || byPrev.has(r.prevHash)) return { rows, linked: false, reordered: 0 };
    byPrev.set(r.prevHash, r);
  }
  const ordered = [];
  let cursor = start;
  for (let i = 0; i < rows.length; i++) {
    const next = byPrev.get(cursor);
    if (!next) return { rows, linked: false, reordered: 0 };
    ordered.push(next);
    cursor = next.hash;
  }
  let reordered = 0;
  for (let i = 0; i < rows.length; i++) if (ordered[i] !== rows[i]) reordered++;
  return { rows: ordered, linked: true, reordered };
}

function createStreamingLinker(startHash = 'GENESIS', { maxPending = 100000 } = {}) {
  let cursor = startHash;
  const held = new Map(); // prevHash -> row
  let inversions = 0;
  return {
    push(rows) {
      const out = [];
      for (const row of rows) {
        if (row.prevHash === cursor) {
          out.push(row);
          cursor = row.hash;
          while (held.has(cursor)) {
            const next = held.get(cursor);
            held.delete(cursor);
            out.push(next);
            cursor = next.hash;
          }
        } else {
          if (held.has(row.prevHash)) {
            // two rows claiming the same parent: a fork — surface it, never hide it
            /** @type {any} */ const err = new Error(`HASH_LINK_FORK: two rows claim prevHash ${row.prevHash}`);
            err.code = 'HASH_LINK_FORK';
            throw err;
          }
          held.set(row.prevHash, row);
          inversions++;
          if (held.size > maxPending) {
            /** @type {any} */ const err = new Error(`HASH_LINK_PENDING_OVERFLOW: more than ${maxPending} rows are waiting for a parent`);
            err.code = 'HASH_LINK_PENDING_OVERFLOW';
            throw err;
          }
        }
      }
      return out;
    },
    cursor: () => cursor,
    pending: () => [...held.values()],
    inversions: () => inversions,
  };
}

module.exports = { orderByHashLinks, createStreamingLinker };
