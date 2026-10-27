'use strict';

// Oracle: with no resolvable key, verifyChain can never return ok:true, whatever the chain looks like, and never throws.
const { verifyChain } = require('../../src/core/delegation/delegationToken');

module.exports.fuzz = function (data) {
  let chain;
  try { chain = JSON.parse(data.toString('utf8')); } catch { return; }
  const r = verifyChain(chain, { now: 1_800_000_000_000, resolveKey: () => null, keyCheck: () => ({ ok: true }) });
  if (!r || r.ok !== false) throw new Error('a chain verified without any trusted key');
  if (typeof r.reason !== 'string') throw new Error('refusal without a reason code');
};
