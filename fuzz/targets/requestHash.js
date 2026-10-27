'use strict';

// Oracle: computeRequestHash is deterministic, case-insensitive in the method, and only ever throws TypeError (never another class).
const { FuzzedDataProvider } = require('@jazzer.js/core');
const { computeRequestHash } = require('../../src/validation/requestHash');

module.exports.fuzz = function (data) {
  const p = new FuzzedDataProvider(data);
  const method = p.consumeString(8);
  const path = p.consumeString(64);
  let body;
  try { body = JSON.parse(p.consumeRemainingAsString()); } catch { body = {}; }
  let h1;
  try { h1 = computeRequestHash(method, path, body); } catch (e) { if (e instanceof TypeError) return; throw e; }
  if (!/^[0-9a-f]{64}$/.test(h1)) throw new Error(`not a SHA-256 hex digest: ${h1}`);
  if (computeRequestHash(method, path, body) !== h1) throw new Error('not deterministic');
  if (computeRequestHash(method.toLowerCase(), path, body) !== computeRequestHash(method.toUpperCase(), path, body)) throw new Error('method case changes the hash');
};
