'use strict';

// Oracle: sortedJSON is deterministic and independent of key insertion order (the property the signatures rely on).
const { sortedJSON } = require('../../src/infra/crypto/hashing');

function reorder(v, flip) {
  if (Array.isArray(v)) return v.map((x) => reorder(x, flip));
  if (v && typeof v === 'object') {
    const keys = Object.keys(v);
    if (flip) keys.reverse();
    const out = {};
    for (const k of keys) out[k] = reorder(v[k], flip);
    return out;
  }
  return v;
}

module.exports.fuzz = function (data) {
  let v;
  try { v = JSON.parse(data.toString('utf8')); } catch { return; }
  let a;
  try { a = sortedJSON(v); } catch (e) { if (e instanceof TypeError || e instanceof RangeError) return; throw e; }
  if (sortedJSON(reorder(v, true)) !== a) throw new Error('key order changes the serialisation');
  if (sortedJSON(v) !== a) throw new Error('not deterministic');
};
