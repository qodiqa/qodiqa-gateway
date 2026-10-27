'use strict';

// Oracle: arbitrary strings never throw and are never accepted as an operator session (a MAC is needed and none can be forged by chance).
const { verify, looksLikeSession, PREFIX } = require('../../src/core/identity/operatorSession');

module.exports.fuzz = function (data) {
  const s = data.toString('latin1');
  for (const token of [s, PREFIX + s, `${PREFIX}${s.slice(0, s.length >> 1)}.${s.slice(s.length >> 1)}`]) {
    const r = verify(token);
    if (r.ok !== false) throw new Error('a fuzzed token was accepted as an operator session');
    if (typeof looksLikeSession(token) !== 'boolean') throw new Error('looksLikeSession is not boolean');
  }
};
