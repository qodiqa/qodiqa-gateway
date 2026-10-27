'use strict';

/**
 * per-stream embedding memo.
 *
 * The streaming output window re-classifies its trailing 4,000-character span every 400 new characters
 * (src/streaming/outputSemanticWindow.js). Every window's vector is a pure, deterministic function of the window's
 * text, so within ONE stream a window
 * string that was already embedded can reuse its vector: identical vector → identical scores → identical decisions
 * and blocking points, by construction. Nothing about WHICH windows are checked changes.
 *
 * For a stream up to 4,000 characters (the audit's 3 KB case) the trailing span always starts at offset 0, so every
 * earlier full window recurs exactly and each check embeds only the window(s) that are new. Longer streams slide the
 * span and reuse less.
 *
 * Scope: a memo exists only inside run(memo, fn) — AsyncLocalStorage, so concurrent streams never share one. Bounded
 * LRU (MAX_ENTRIES per model). Consulted by embeddingBackend.embed()/embedBatch() and ft3Gate.embed().
 */

const { AsyncLocalStorage } = require('async_hooks');

const MAX_ENTRIES = 512;
const _als = new AsyncLocalStorage();

function create(maxEntries = MAX_ENTRIES) {
  return { minilm: new Map(), ft3: new Map(), max: maxEntries, hits: 0, misses: 0 };
}
function run(memo, fn) { return _als.run(memo, fn); }
function current() { return _als.getStore() || null; }

function get(kind, text) {
  const m = current(); if (!m) return undefined;
  const map = m[kind]; const v = map.get(text);
  if (v === undefined) { m.misses++; return undefined; }
  map.delete(text); map.set(text, v); // LRU refresh
  m.hits++;
  return v.slice();
}
function set(kind, text, vector) {
  const m = current(); if (!m) return;
  const map = m[kind];
  map.set(text, Array.from(vector));
  while (map.size > m.max) map.delete(map.keys().next().value);
}

module.exports = { create, run, current, get, set, MAX_ENTRIES };
