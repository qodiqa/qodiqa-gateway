'use strict';

/** the transparency signer's Prometheus counters, exported but never written, are now live. */

const crypto = require('crypto');
const metrics = require('../metrics');
const signerMod = require('../../core/transparency/transparencySigner');
const tKeyStore = require('../../core/transparency/transparencyKeyStore');

describe('transparency signer metrics', () => {
  test('LM-01 sign/verify/rotate are mirrored to qodiqa_transparency_signer_* and appear on /metrics', async () => {
    tKeyStore.rotateKey(); // provision
    const signer = new signerMod.SoftwareTransparencySigner();
    const h = crypto.createHash('sha256').update('x').digest();
    const { signature, keyId } = await signer.sign(h);
    expect(signer.verify(h, signature, keyId)).toBe(true);
    tKeyStore.rotateKey();
    signer.rotate();
    const text = metrics.collect(0);
    expect(text).toMatch(/qodiqa_transparency_signer_signatures_total [1-9]/);
    expect(text).toMatch(/qodiqa_transparency_signer_key_rotations_total [1-9]/);
  });
});
