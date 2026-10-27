'use strict';

// Oracle (documented contract of parseTimestamp): never throws, always a number, NaN for everything unparseable, a finite result that is not positive must be refused by checkSkew.
// Recorded deviation F12-FZ-01: strings parse to 0 ("0") or to a negative time (an ISO date before 1970) although the number 0 is NaN; checkSkew is what must refuse it (it does).
const { FuzzedDataProvider } = require('@jazzer.js/core');
const { parseTimestamp, checkSkew } = require('../../src/validation/timeCheck');

module.exports.fuzz = function (data) {
  const p = new FuzzedDataProvider(data);
  const inputs = [p.consumeNumber(), p.consumeIntegral(6), p.consumeString(40), p.consumeBoolean(), null, undefined, {}, []];
  for (const x of inputs) {
    const r = parseTimestamp(x);
    if (typeof r !== 'number') throw new Error(`parseTimestamp(${String(x).slice(0, 30)}) returned a ${typeof r}`);
    if (Number.isFinite(r) && r <= 0 && checkSkew(x, Date.now()).valid) throw new Error('a non-positive time passed checkSkew');
    if ((typeof x === 'boolean' || x === null || x === undefined || typeof x === 'object') && !Number.isNaN(r)) throw new Error('a non-string, non-number input parsed as a time');
  }
};
