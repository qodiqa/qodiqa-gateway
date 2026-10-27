'use strict';

// Oracle: parseJcsP1 either throws a JcsError or returns a value whose canonical form is a fixed point of parse -> canonical.
const { parseJcsP1, canonicalJcsP1, JcsError } = require('../../src/validation/jcsP1');

module.exports.fuzz = function (data) {
  let r;
  try { r = parseJcsP1(data); } catch (e) { if (e instanceof JcsError) return; throw e; }
  const again = parseJcsP1(r.canonical);
  if (again.canonical !== r.canonical) throw new Error('canonical form is not a fixed point');
  if (canonicalJcsP1(r.value) !== r.canonical) throw new Error('canonicalJcsP1(value) differs from the parse result');
};
