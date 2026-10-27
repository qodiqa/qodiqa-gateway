'use strict';

const crypto = require('crypto');

function sign(hashBuffer, privDer) {
  if (!Buffer.isBuffer(hashBuffer) || hashBuffer.length !== 32) {
    throw new TypeError('sign(): hashBuffer must be a 32-byte Buffer');
  }
  if (!Buffer.isBuffer(privDer) || privDer.length === 0) {
    throw new TypeError('sign(): privDer must be a non-empty Buffer');
  }
  const privKey = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  return crypto.sign(null, hashBuffer, privKey).toString('base64');
}

function verify(hashBuffer, signatureBase64, pubDer) {
  try {
    if (!Buffer.isBuffer(hashBuffer) || hashBuffer.length !== 32) return false;
    if (typeof signatureBase64 !== 'string')                       return false;
    if (!Buffer.isBuffer(pubDer) || pubDer.length === 0)           return false;
    const sigBuf = Buffer.from(signatureBase64, 'base64');
    if (sigBuf.length !== 64) return false;
    const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
    return crypto.verify(null, hashBuffer, pubKey, sigBuf);
  } catch {
    return false;
  }
}

module.exports = { sign, verify };
