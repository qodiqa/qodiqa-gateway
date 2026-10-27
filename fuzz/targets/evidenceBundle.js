'use strict';

// Oracle: the standalone offline verifier (the file an auditor is given) never reports valid:true without trust anchors, and never throws on hostile JSON.
const { verifyEvidenceBundle, verifyEvidencePackage } = require('../../tools/verify/verify.bundle.external.js');

module.exports.fuzz = function (data) {
  let b;
  try { b = JSON.parse(data.toString('utf8')); } catch { return; }
  const r = verifyEvidenceBundle(b, {});
  if (!r || r.valid !== false) throw new Error('bundle reported valid without trust anchors');
  const p = verifyEvidencePackage(b && b.evidencePackage ? b.evidencePackage : b, {});
  if (p && p.valid === true) throw new Error('package reported valid without trust anchors');
};
