'use strict';

// publishAnchor's opt-in requireCosignature. With witnesses configured and none cosigning, the
// opt-in writes NOTHING (an unwitnessed record fails every production boot with ANCHOR_NOT_WITNESSED, and no bootstrap
// clears it); the default keeps the long-standing behaviour (the record is written and kept as evidence).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { publishAnchor, readAnchors } = require('../anchors');

const checkpoint = { payload: { checkpointId: 'cp-1', chainLength: 10, headHash: 'a'.repeat(64) }, payloadHash: 'b'.repeat(64), signature: 'c'.repeat(88) };
const failing = { witnessId: 'w1', cosign: async () => { const e = new Error('EPERM: operation not permitted, link'); e.code = 'EPERM'; throw e; } };
const working = { witnessId: 'w1', cosign: async () => ({ witnessId: 'w1', signature: 'sig' }) };

let dir;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aut06-pub-')); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });
const exp = () => path.join(dir, 'anchors.jsonl');
const trusted = { keys: [] };

test('RC-1 requireCosignature + every witness fails → nothing written, errors reported', async () => {
  const r = await publishAnchor(checkpoint, { witnesses: [failing], exportPath: exp(), trustedWitnessKeys: trusted, requireCosignature: true });
  expect(r.record).toBeNull();
  expect(r.errors).toEqual([expect.objectContaining({ witnessId: 'w1', code: 'EPERM' })]);
  expect(fs.existsSync(exp())).toBe(false);
});

test('RC-2 default (no opt-in) + every witness fails → the record is still written (unchanged behaviour)', async () => {
  const r = await publishAnchor(checkpoint, { witnesses: [failing], exportPath: exp(), trustedWitnessKeys: trusted });
  expect(r.record).not.toBeNull();
  expect(r.record.cosignatures).toEqual([]);
  expect(readAnchors(exp())).toHaveLength(1);
});

test('RC-3 requireCosignature + a working witness → written with its cosignature', async () => {
  const r = await publishAnchor(checkpoint, { witnesses: [working], exportPath: exp(), trustedWitnessKeys: trusted, requireCosignature: true });
  expect(r.record.cosignatures).toHaveLength(1);
  expect(readAnchors(exp())).toHaveLength(1);
});
